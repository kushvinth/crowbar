# crowbar intro demo - render a real recording with charmbracelet/vhs:
#   vhs assets/demo.tape        (needs: crowbar installed + an index built)
# Produces docs/assets/demo.gif (+ mp4/webm). Requires ffmpeg + ttyd (vhs deps).
Output docs/assets/demo.gif
Output assets/demo.mp4
Output assets/demo.webm

Set Theme "Catppuccin Mocha"
Set FontSize 16
Set Width 1240
Set Height 780
Set Padding 24
Set TypingSpeed 45ms
Set PlaybackSpeed 1.0

Hide
Type "clear" Enter
Show

Type "crowbar cve CVE-2021-44228" Sleep 500ms Enter Sleep 3.5s
Type "crowbar product nginx --version 1.18.0" Sleep 500ms Enter Sleep 3s
Type "crowbar exploit log4j" Sleep 500ms Enter Sleep 2.5s
Sleep 1s
