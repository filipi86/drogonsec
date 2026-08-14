# VHS tape for the banner shown in README.md and docs/index.md.
#
# This file is the source of the image. Do not replace the GIF with a
# hand-taken screenshot: the version string is baked into the banner, so a
# manual capture goes stale at every release and nobody notices until someone
# reads the README. Regenerate instead:
#
#     make demo            # needs vhs on PATH: brew install vhs
#
# .github/workflows/release-assets.yml runs the same target when a release is
# published and opens a pull request with the result.
#
# Requires vhs (https://github.com/charmbracelet/vhs).

Output docs/assets/banner.gif

Set Shell "bash"
Set FontSize 14
Set Padding 12
Set TypingSpeed 55ms

# The banner frame is 84 columns wide. The window is deliberately wider than
# that: too narrow wraps every line and the box collapses into noise, while too
# wide only leaves margin. Height covers the 29 banner lines plus the prompt
# and the three version lines under it.
Set Width 820
Set Height 610

# Put the freshly built binary on PATH without showing the plumbing, so the
# recording opens on a clean prompt.
Hide
Type 'export PATH="$PWD/bin:$PATH"'
Enter
Type "clear"
Enter
Show

Type "drogonsec version"
Sleep 500ms
Enter
Sleep 4s
