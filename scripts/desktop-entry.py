import sys

if len(sys.argv) == 2 and sys.argv[1] == "--check-evidence-ui":
    from eraseproof.ui_check import main
    raise SystemExit(main())
elif len(sys.argv) > 1 and sys.argv[1] == "--cli":
    from eraseproof.cli import main
    raise SystemExit(main(sys.argv[2:]))
else:
    from eraseproof.desktop import main
    raise SystemExit(main())
