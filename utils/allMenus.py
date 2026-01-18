from sessions.mangmant_sessions import create_session, history_session
from utils.color import RED, GREEN, RESET, BLUE
from utils.util import clear_screen


def mainMenu():
    clear_screen()
    menuOp = [
        f'{GREEN}1-Session Menu{RESET}',
        f'{GREEN}2-About Tool\n{RESET}'
        f'{RED}00-Exit{RESET}',
    ]
    for op in menuOp:
        print(op)
    x = int(input(f"{BLUE} Enter select options: {RESET}"))
    match x:
        case 1:
            sessionMenu()
        case 2:
            aboutMenu()
        case 00:
            exit(0)


def sessionMenu():
    clear_screen()
    sOp = [
        f'{GREEN}1-Create New Session{RESET}',
        f'{GREEN}2-History Session\n{RESET}',
        f'{RED}00-Back{RESET}',
    ]
    for op in sOp:
        print(op)
    op = int(input(f"{BLUE} Enter select options: {RESET}"))
    match op:
        case 1:
            create_session()
        case 2:
            history_session()
        case 00:
            mainMenu()


def aboutMenu():
    print(""" v1""")

    pass
