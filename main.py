import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def main():
    try:
        import Crypto  # noqa
    except ImportError:
        print("Instalirajte: pip install pycryptodome"); sys.exit(1)
    from gui.app import run
    run()

if __name__ == "__main__":
    main()