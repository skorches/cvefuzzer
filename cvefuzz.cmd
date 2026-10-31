@echo off
"%~dp0.tools\python\python.exe" -c "import sys; sys.path.insert(0,sys.argv.pop(1)); from cvefuzz.cli import main; sys.exit(main())" "%~dp0src" %*
exit /b %errorlevel%
