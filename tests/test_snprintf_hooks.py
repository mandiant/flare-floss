from unittest.mock import MagicMock, patch

import pytest

from floss.api_hooks import MAX_STR_SIZE, SnprintfHook


class MockEmulator:
    """Mock emulator for testing hooks without vivisect dependency."""

    def __init__(self):
        self.memory = {}
        self.return_value = None

    def writeMemory(self, addr, data):
        self.memory[addr] = data

    def readMemory(self, addr, size):
        return self.memory.get(addr, b"\x00" * size)[:size]


class TestSnprintfHook:
    """Tests for SnprintfHook._prepare_args and __call__"""

    @pytest.fixture
    def hook(self):
        return SnprintfHook()

    @pytest.fixture
    def emu(self):
        return MockEmulator()

    def test_prepare_args_integer(self, hook, emu):
        """Test %d format specifier"""
        fmt = "Value: %d"
        argv = [0, 64, 0, 42]  # buf, size, fmt, value
        args = hook._prepare_args(emu, fmt, argv, arg_start_idx=3)
        assert args == (42,)

    def test_prepare_args_negative_integer(self, hook, emu):
        """Test %d with negative value (unsigned to signed conversion)"""
        fmt = "Value: %d"
        # 0xFFFFFF85 = 4294967173 (unsigned representation of -123)
        argv = [0, 64, 0, 0xFFFFFF85]
        args = hook._prepare_args(emu, fmt, argv, arg_start_idx=3)
        assert args == (-123,)

    def test_prepare_args_hex(self, hook, emu):
        """Test %x format specifier"""
        fmt = "Hex: %x"
        argv = [0, 64, 0, 255]
        args = hook._prepare_args(emu, fmt, argv, arg_start_idx=3)
        assert args == (255,)

    def test_prepare_args_unsigned(self, hook, emu):
        """Test %u format specifier with large unsigned value"""
        fmt = "Unsigned: %u"
        argv = [0, 64, 0, 0xFFFFFFFF]
        args = hook._prepare_args(emu, fmt, argv, arg_start_idx=3)
        assert args == (0xFFFFFFFF,)

    def test_prepare_args_string(self, hook, emu):
        """Test %s format specifier (reads from memory)"""
        fmt = "Name: %s"
        string_ptr = 0x1000
        emu.memory[string_ptr] = b"TestString\x00"

        argv = [0, 64, 0, string_ptr]

        with patch("floss.api_hooks.fu.readStringAtRva") as mock_read:
            mock_read.return_value = b"TestString"
            args = hook._prepare_args(emu, fmt, argv, arg_start_idx=3)
            assert args == ("TestString",)

    def test_prepare_args_null_string(self, hook, emu):
        """Test %s with NULL pointer"""
        fmt = "Name: %s"
        argv = [0, 64, 0, 0]  # NULL pointer
        args = hook._prepare_args(emu, fmt, argv, arg_start_idx=3)
        assert args == ("(null)",)

    def test_prepare_args_multiple(self, hook, emu):
        """Test multiple format specifiers"""
        fmt = "User: %s, Port: %d"
        string_ptr = 0x1000

        argv = [0, 64, 0, string_ptr, 8080]

        with patch("floss.api_hooks.fu.readStringAtRva") as mock_read:
            mock_read.return_value = b"admin"
            args = hook._prepare_args(emu, fmt, argv, arg_start_idx=3)
            assert args == ("admin", 8080)

    def test_prepare_args_percent_escape(self, hook, emu):
        """Test %% escape sequence (should not consume argument)"""
        fmt = "100%% complete: %d"
        argv = [0, 64, 0, 42]
        args = hook._prepare_args(emu, fmt, argv, arg_start_idx=3)
        assert args == (42,)

    def test_prepare_args_width_modifier(self, hook, emu):
        """Test format specifier with width modifier"""
        fmt = "Padded: %08x"
        argv = [0, 64, 0, 255]
        args = hook._prepare_args(emu, fmt, argv, arg_start_idx=3)
        assert args == (255,)


class TestSnprintfHookCall:
    """Tests for the full __call__ method"""

    @pytest.fixture
    def hook(self):
        return SnprintfHook()

    @pytest.fixture
    def emu(self):
        return MockEmulator()

    def test_snprintf_basic(self, hook, emu):
        """Test snprintf call writes formatted string to memory"""
        buf_ptr = 0x2000
        fmt_ptr = 0x1000

        api = (None, None, None, "snprintf", [])
        argv = [buf_ptr, 64, fmt_ptr, 42]

        with (
            patch("floss.api_hooks.fu.contains_funcname") as mock_contains,
            patch("floss.api_hooks.fu.readStringAtRva") as mock_read,
            patch("floss.api_hooks.fu.call_return") as mock_return,
        ):

            mock_contains.side_effect = lambda api, names: "snprintf" in names
            mock_read.return_value = b"Value: %d"

            result = hook(emu, api, argv)

            assert result == True
            assert buf_ptr in emu.memory
            assert emu.memory[buf_ptr] == b"Value: 42\x00"

    def test_sprintf_basic(self, hook, emu):
        """Test sprintf call (no size parameter)"""
        buf_ptr = 0x2000
        fmt_ptr = 0x1000

        api = (None, None, None, "sprintf", [])
        argv = [buf_ptr, fmt_ptr, 1337]

        with (
            patch("floss.api_hooks.fu.contains_funcname") as mock_contains,
            patch("floss.api_hooks.fu.readStringAtRva") as mock_read,
            patch("floss.api_hooks.fu.call_return") as mock_return,
        ):

            # Mock: first call checks if any of snprintf/sprintf
            # Second call checks if "sprintf" is in names
            # Third call checks if "snprintf" is in names (should return False for sprintf)
            def contains_check(api, names):
                # Check if "sprintf" is in the tuple (matches sprintf, snprintf,)
                if "sprintf" in names:
                    return True
                if "snprintf" in names:
                    return False  # sprintf is NOT snprintf
                return False

            mock_contains.side_effect = contains_check
            mock_read.return_value = b"Code: %d"

            result = hook(emu, api, argv)

            assert result == True
            assert buf_ptr in emu.memory
            assert emu.memory[buf_ptr] == b"Code: 1337\x00"
