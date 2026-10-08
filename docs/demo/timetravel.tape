# The README's time-travel demo: replay the demo recording from its healthy
# start and step forward through it until the problems appear. Run from the
# repository root:
#
#   vhs docs/demo/timetravel.tape
#
# (VHS_NO_SANDBOX=true where Chromium's sandbox can't start.)
Output docs/demo/timetravel.gif

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
Sleep 2s

# Back to the start of the recording: healthy.
Type "{"
Sleep 300ms
Type "{"
Sleep 300ms
Type "{"
Sleep 2.5s

# Step forward a poll at a time.
Type@500ms "]]]]]]]]]]]]"
Sleep 2.5s
Type@500ms "]]]]]]"
Sleep 3s
Type "q"
Sleep 500ms
