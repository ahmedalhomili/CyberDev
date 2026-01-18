import sys
from utils.color import GREEN, CYAN, RESET, YELLOW

class ProgressBar:
    """
    Call in a loop to create terminal progress bar
    @params:
        iteration   - Required  : current iteration (Int)
        total       - Required  : total iterations (Int)
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : positive number of decimals in percent complete (Int)
        length      - Optional  : character length of bar (Int)
        fill        - Optional  : bar fill character (Str)
        printEnd    - Optional  : end character (e.g. "\r", "\r\n") (Str)
    """
    def __init__(self, total, prefix='', suffix='', decimals=1, length=50, fill='█', printEnd="\r"):
        self.total = total
        self.prefix = prefix
        self.suffix = suffix
        self.decimals = decimals
        self.length = length
        self.fill = fill
        self.printEnd = printEnd

    def update(self, iteration, action_description=""):
        percent = ("{0:." + str(self.decimals) + "f}").format(100 * (iteration / float(self.total)))
        filledLength = int(self.length * iteration // self.total)
        
        # Color the bar
        bar = self.fill * filledLength + '-' * (self.length - filledLength)
        
        # Format: Prefix |██████----| 60.0% Action Description
        # \033[K clears to end of line to remove artifacts from previous longer lines
        sys.stdout.write(f'\r{self.prefix} |{GREEN}{bar}{RESET}| {percent}% {CYAN}{action_description}{RESET} {self.suffix}\033[K')
        sys.stdout.flush()
        
        if iteration == self.total:
            print()
