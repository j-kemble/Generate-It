"""Non-interactive smoke test for the curses TUI entrypoint.

The goal is to drive ``generate_it.tui.run()`` without a real terminal: we
replace the ``curses`` module everywhere it is imported with a ``MagicMock``,
inject a fake ``stdscr`` through ``curses.wrapper``, and drive the app to a
clean exit. This raises coverage of ``tui.py`` (and the render/modal helpers)
well above the old baseline and guards against future crashes in the main loop
and the vault unlock path.

How the run is forced to a clean exit:

* The dashboard main loop idles on ``getch() == -1`` (``continue``) and quits on
  a double ``Esc`` (``27``). We feed ``[27, 27]`` so it exits via ``return 0``.
* The vault-unlock modal is rendered in a sub-window created with
  ``curses.newwin(...)``; its ``getch()`` returns ``10`` (Enter) so the modal
  "confirms" the (empty) password and the unlock flow proceeds instead of
  looping forever waiting for input. The mocked ``StorageManager`` accepts the
  unlock without touching the filesystem.
"""

import pytest
from unittest import mock

import generate_it.tui as tui


def _make_fake_stdscr() -> mock.MagicMock:
    stdscr = mock.MagicMock(name="stdscr")
    # Most draw code does ``h, w = stdscr.getmaxyx()`` so it must return a tuple.
    stdscr.getmaxyx.return_value = (40, 120)
    stdscr.getbegyx.return_value = (0, 0)
    # Double-Esc quits the dashboard loop; the trailing -1 is never consumed.
    stdscr.getch.side_effect = [27, 27, -1]
    return stdscr


def test_tui_run_smoke_no_tty() -> None:
    fake_stdscr = _make_fake_stdscr()

    # A single mocked curses module shared by every submodule that imports it.
    fake_curses = mock.MagicMock(name="curses")
    # Avoid the color-init branch; _init_theme then takes the safe fallback path.
    fake_curses.has_colors.return_value = False
    # curses.wrapper injects our fake stdscr into the real entrypoint.
    fake_curses.wrapper.side_effect = lambda fn, *a, **k: fn(fake_stdscr)
    # Modal sub-windows built via newwin() "confirm" (Enter == 10) so the
    # unlock flow advances instead of blocking on user input.
    fake_curses.newwin.return_value.getch.return_value = 10

    fake_storage = mock.MagicMock(name="StorageManager")
    fake_storage.vault_exists.return_value = True
    fake_storage.get_failed_unlock_state.return_value = (0, None)
    # tui.run() instantiates StorageManager(...); return the same configured mock.
    fake_storage.return_value = fake_storage

    with mock.patch("generate_it.tui.curses", fake_curses), \
         mock.patch("generate_it.tui_render.curses", fake_curses), \
         mock.patch("generate_it.tui_modal.curses", fake_curses), \
         mock.patch("generate_it.tui_security.curses", fake_curses), \
         mock.patch("generate_it.tui_csv.curses", fake_curses), \
         mock.patch("generate_it.tui.StorageManager", fake_storage):
        result = tui.run()

    assert result == 0


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
