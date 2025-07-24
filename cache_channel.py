from sys import exit
from src.Core import CachingChannel


def intro() -> None:
    output: str = f"""
                   [ Private Use Only ]

 ██████╗ █████╗  ██████╗██╗  ██╗███████╗      ██████╗██████╗     
██╔════╝██╔══██╗██╔════╝██║  ██║██╔════╝     ██╔════╝╚════██╗    
██║     ███████║██║     ███████║█████╗       ██║      █████╔╝    
██║     ██╔══██║██║     ██╔══██║██╔══╝       ██║     ██╔═══╝     
╚██████╗██║  ██║╚██████╗██║  ██║███████╗     ╚██████╗███████╗    
 ╚═════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝      ╚═════╝╚══════╝    
                                                                
  ██████╗██╗  ██╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██╗     
 ██╔════╝██║  ██║██╔══██╗████╗  ██║████╗  ██║██╔════╝██║     
 ██║     ███████║███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██║     
 ██║     ██╔══██║██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██║     
 ╚██████╗██║  ██║██║  ██║██║ ╚████║██║ ╚████║███████╗███████╗
  ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚══════╝
                                                                
           [ Proof of Concept | d3d | @deadvolvo ]
           
  ══════════════════════════════════════════════════════════ 
  
"""
    print(output)


def options() -> None:
    output: str = f"""
Options:
-------
'-u', '--url'       - [str]  Set the URL of the vulnerable server
'-l', '--listener'  - [bool] Set the listener to poll for global cache content
'-s', '--sender'    - [bool] Set the sender status (will be asked to supply file)

"""
    print(output)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(add_help=False, usage=None)
    parser.add_argument('-u', '--url', dest='url', action='store', type=str, default='')
    parser.add_argument('-l', '--listener', dest='listener', action='store_true', default=False)
    parser.add_argument('-s', '--sender', dest='sender', action='store_true', default=False)

    arg = None

    try:
        arg = parser.parse_args()
        intro()
        if not arg.url or (not arg.listener and not arg.sender):
            exit(options())
    except TypeError:
        exit(options())

    try:
        handler = CachingChannel(arg.url, arg.listener, arg.sender)
    except KeyboardInterrupt:
        print("\n[!] Breaking due to user-exception...\n")
