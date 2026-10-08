# The README's triage demo: replay the demo recording (web-1.jsonl.gz, made
# by the lab's TestDemo), walk the ranked findings, jump to the affected
# socket and its history. Run from the repository root:
#
#   vhs docs/demo/triage.tape
#
# (VHS_NO_SANDBOX=true where Chromium's sandbox can't start.)
Output docs/demo/triage.gif

Set Shell "bash"
Set FontFamily "DejaVu Sans Mono"
Set FontSize 14
Set Width 1320
Set Height 540
Set Padding 12
Set Framerate 24
Set TypingSpeed 45ms

Hide
Type "go build -o /tmp/sstui-demo/sstui . && export PATH=/tmp/sstui-demo:$PATH && clear"
Enter
Sleep 8s
Show

Type "sstui replay docs/demo/web-1.jsonl.gz"
Sleep 500ms
Enter
Sleep 4.5s

# The next findings: the accept queue, then the lossy path.
Type "j"
Sleep 3.5s
Type "j"
Sleep 4.5s

# Enter: just the affected socket, in Live.
Enter
Sleep 3s

# Enter again: the connection; 4: its queues, memory and history.
Enter
Sleep 300ms
Type "4"
Sleep 5s

Type "1"
Sleep 1.5s
Type "q"
Sleep 500ms
