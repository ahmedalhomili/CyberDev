"""
Scan progress handler for CLI/interactive mode.
"""
import sys
from ui.colors import RED, GREEN, RESET, YELLOW, CYAN, MAGENTA, GRAY


class ScanProgress:
    """Manage and render scan progress updates."""

    def __init__(self) -> None:
        self.last_msg = None
        self.last_step = 0
        self.last_stats = None

    def handle(self, step: int, total: int, msg: str, prev_stats=None) -> None:
        """Progress callback passed to the scanner."""
        # Clear current line (Active Progress Bar)
        sys.stdout.write('\r' + ' ' * 100 + '\r')

        # If we moved to a new step, mark the previous one as done
        if self.last_msg and step > self.last_step:
            symbol = f"{GREEN}[✓]{RESET}"

            if prev_stats is not None:
                count = prev_stats.get('count', 0)
                severity = prev_stats.get('max_severity', 'INFO')

                if count > 0:
                    color = GREEN
                    if severity == 'LOW':
                        color = CYAN
                    elif severity == 'MEDIUM':
                        color = YELLOW
                    elif severity == 'HIGH':
                        color = RED
                    elif severity == 'CRITICAL':
                        color = MAGENTA

                    symbol = f"{color}[✓]{RESET}"
                else:
                    symbol = f"{GRAY}[✗]{RESET}"

            print(f"{symbol} {self.last_msg}")

        # Draw progress bar for current step
        percent = 100 * (step / float(total))
        if percent > 100:
            percent = 100
        bar_len = 30
        filled = int(bar_len * step // total)
        if filled > bar_len:
            filled = bar_len
        bar = '█' * filled + '░' * (bar_len - filled)

        sys.stdout.write(
            f"{CYAN}[Step {step:02d}/{total}]{RESET} "
            f"[{GREEN}{bar}{RESET}] {percent:3.0f}% {msg}"
        )
        sys.stdout.flush()

        self.last_msg = msg
        self.last_step = step
        self.last_stats = prev_stats

    def finalize(self) -> None:
        """Finalize the last progress line."""
        sys.stdout.write('\r' + ' ' * 100 + '\r')
        if self.last_msg and "Scan Finished" not in self.last_msg:
            print(f"{GREEN}[✓]{RESET} {self.last_msg}")
