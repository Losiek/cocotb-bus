# Copyright cocotb contributors
# Copyright (c) 2013 Potential Ventures Ltd
# Copyright (c) 2013 SolarFlare Communications Inc
# Licensed under the Revised BSD License, see LICENSE for details.
# SPDX-License-Identifier: BSD-3-Clause

"""Monitors for Intel Avalon interfaces.

See https://www.intel.com/content/dam/www/programmable/us/en/pdfs/literature/manual/mnl_avalon_spec_1_3.pdf

NB Currently we only support a very small subset of functionality.
"""

import warnings

from cocotb.utils import hexdump
from cocotb.triggers import RisingEdge, Event
from cocotb.binary import BinaryValue

from cocotb_bus.monitors import BusMonitor


class AvalonProtocolError(Exception):
    pass


class AvalonST(BusMonitor):
    """Avalon-ST bus.

    Non-packetized so each valid word is a separate transaction.
    """

    _signals = ["valid", "data"]
    _optional_signals = ["ready"]

    _default_config = {"firstSymbolInHighOrderBits": True}

    def __init__(self, entity, name, clock, *, config={}, **kwargs):
        BusMonitor.__init__(self, entity, name, clock, **kwargs)

        self.config = self._default_config.copy()

        for configoption, value in config.items():
            self.config[configoption] = value
            self.log.debug(f"{self.name}: Setting config option {configoption} to {str(value)}")

    async def _monitor_recv(self):
        """Watch the pins and reconstruct transactions."""

        # Avoid spurious object creation by recycling
        clkedge = RisingEdge(self.clock)

        def valid():
            if hasattr(self.bus, "ready"):
                return self.bus.valid.value and self.bus.ready.value  # type: ignore
            return self.bus.valid.value  # type: ignore

        # NB could await on valid here more efficiently?
        while True:
            await clkedge
            if valid():
                vec = self.bus.data.value  # type: ignore
                vec.big_endian = self.config["firstSymbolInHighOrderBits"]
                self._recv(vec.buff)


class AvalonSTPkts(BusMonitor):
    """Packetized Avalon-ST bus.

    Args:
        entity, name, clock: see :class:`BusMonitor`
        config (dict): bus configuration options
        report_channel (bool): report channel with data, default is False
            Setting to True on bus without channel signal will give an error
    """

    _signals = ["valid", "data", "startofpacket", "endofpacket"]
    _optional_signals = ["error", "channel", "ready", "empty"]

    _default_config = {
        "dataBitsPerSymbol": 8,
        "firstSymbolInHighOrderBits": True,
        "maxChannel": 0,
        "readyLatency": 0,
        "invalidTimeout": 0,
    }

    def __init__(
        self,
        entity,
        name,
        clock,
        *,
        config={},
        report_channel=False,
        error_cb=None,
        **kwargs,
    ):
        BusMonitor.__init__(self, entity, name, clock, **kwargs)

        self.config = self._default_config.copy()
        self.report_channel = report_channel

        # Set default config maxChannel to max value on channel bus
        if hasattr(self.bus, "channel"):
            self.config["maxChannel"] = (2 ** len(self.bus.channel)) - 1  # type: ignore
        else:
            if report_channel:
                raise ValueError(
                    "{self.name}: Channel reporting asked on bus without channel signal"
                )

        for configoption, value in config.items():
            self.config[configoption] = value
            self.log.debug(f"{self.name}: Setting config option {configoption} to {str(value)}")

        num_data_symbols = len(self.bus.data) / self.config["dataBitsPerSymbol"]  # type: ignore
        if num_data_symbols > 1 and not hasattr(self.bus, "empty"):
            raise AttributeError(
                f"{self.name}: has {num_data_symbols} data symbols, but contains no object named empty"
            )

        self.config["useEmpty"] = num_data_symbols > 1

        if hasattr(self.bus, "channel"):
            if len(self.bus.channel) > 128:  # type: ignore
                raise AttributeError(
                    "AvalonST interface specification defines channel width as 1-128. "
                    f"{self.name}: channel width is {len(self.bus.channel)}"  # type: ignore
                )
            maxChannel = (2 ** len(self.bus.channel)) - 1  # type: ignore
            if self.config["maxChannel"] > maxChannel:
                raise AttributeError(
                    f"{self.name}: has maxChannel={self.config['maxChannel']}, but can only support a maximum channel of "
                    f"(2**channel_width)-1={maxChannel}, channel_width={len(self.bus.channel)}"  # type: ignore
                )

        self.error_cb = error_cb
        self.in_pkt = Event("in_pkt")

    async def _monitor_recv(self):
        """Watch the pins and reconstruct transactions."""

        # Avoid spurious object creation by recycling
        clkedge = RisingEdge(self.clock)
        pkt = b""
        invalid_cyclecount = 0
        channel = None

        def valid():
            if hasattr(self.bus, "ready"):
                return self.bus.valid.value and self.bus.ready.value  # type: ignore
            return self.bus.valid.value  # type: ignore

        while True:
            await clkedge

            if self.in_reset:
                self.in_pkt.clear()
                pkt = b""
                invalid_cyclecount = 0
                channel = None
                continue

            if valid():
                invalid_cyclecount = 0

                if self.bus.startofpacket.value:  # type: ignore
                    if pkt:
                        raise AvalonProtocolError(
                            f"{self.name}: Duplicate start-of-packet received on {str(self.bus.startofpacket)}"  # type: ignore
                        )
                    pkt = b""
                    self.in_pkt.set()

                if not self.in_pkt.is_set():
                    raise AvalonProtocolError(
                        f"{self.name}: Data transfer outside of packet"
                    )

                # Handle empty and X's in empty / data
                vec = BinaryValue()
                if not self.bus.endofpacket.value:  # type: ignore
                    vec = self.bus.data.value  # type: ignore
                else:
                    value = self.bus.data.value.get_binstr()  # type: ignore
                    empty = None
                    if self.config["useEmpty"] and self.bus.empty.value.integer:  # type: ignore
                        empty = (
                            self.bus.empty.value.integer  # type: ignore
                            * self.config["dataBitsPerSymbol"]
                        )
                        if self.config["firstSymbolInHighOrderBits"]:
                            value = value[:-empty]
                        else:
                            value = value[empty:]
                    vec.assign(value)
                    if not vec.is_resolvable:
                        raise AvalonProtocolError(
                            "After empty masking value is still bad?  "
                            f"{self.name}: Had empty {empty}, got value {self.bus.data.value.get_binstr()}"  # type: ignore
                        )

                vec.big_endian = self.config["firstSymbolInHighOrderBits"]
                pkt += vec.buff

                if hasattr(self.bus, "channel"):
                    if channel is None:
                        channel = self.bus.channel.value.integer  # type: ignore
                        if channel > self.config["maxChannel"]:
                            raise AvalonProtocolError(
                                f"{self.name}: Channel value ({self.config['maxChannel']}) is greater than maxChannel"
                            )
                    elif self.bus.channel.value.integer != channel:  # type: ignore
                        raise AvalonProtocolError(
                            f"{self.name}: Channel value changed during packet"
                        )

                if hasattr(self.bus, "error"):
                    error_value = self.bus.error.value.integer  # type: ignore
                    if error_value != 0:
                        self.log.info(f"{self.name}: Received an error {error_value}")
                        if self.error_cb:
                            self.error_cb(error_value)

                if self.bus.endofpacket.value:  # type: ignore
                    self.log.info(f"{self.name}: Received a packet of {len(pkt)} bytes")
                    self.log.debug(hexdump(pkt))
                    self.channel = channel
                    if self.report_channel:
                        self._recv({"data": pkt, "channel": channel})
                    else:
                        self._recv(pkt)
                    pkt = b""
                    self.in_pkt.clear()
                    channel = None
            else:
                if self.in_pkt.is_set():
                    invalid_cyclecount += 1
                    if self.config["invalidTimeout"]:
                        if invalid_cyclecount >= self.config["invalidTimeout"]:
                            raise AvalonProtocolError(
                                f"{self.name}: In-Packet Timeout. Didn't receive any valid data for {invalid_cyclecount} cycles!"
                            )


class AvalonSTPktsWithChannel(AvalonSTPkts):
    """Packetized AvalonST bus using channel.

    This class is deprecated. Use AvalonSTPkts(..., report_channel=True, ...)
    """

    def __init__(self, entity, name, clock, **kwargs):
        warnings.warn(
            "Use of AvalonSTPktsWithChannel is deprecated\n"
            "\tUse AvalonSTPkts(..., report_channel=True, ...)",
            DeprecationWarning,
            stacklevel=2,
        )
        AvalonSTPkts.__init__(self, entity, name, clock, report_channel=True, **kwargs)
