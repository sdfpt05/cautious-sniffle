#!/usr/bin/env python3
import sys
from cli import cli

if __name__ == '__main__':
    try:
        cli(obj={})
    except KeyboardInterrupt:
        print("\nOperation cancelled by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")
        sys.exit(1)
