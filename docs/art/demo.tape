# The lictor demo - the auditable exploitation decision layer.
# Regenerate BY HAND (never in CI: a bot that commits the gif = push conflicts):
#   docker compose -f lab/docker-compose.yml up -d --build
#   rm -rf /tmp/lictor-demo && mkdir /tmp/lictor-demo
#   printf 'allowlist: targets.yml\ntrail: demo-trail.jsonl\n' > /tmp/lictor-demo/lictor.yml
#   printf '127.0.0.1:9996\n127.0.0.1:9997\n127.0.0.1:9998\n127.0.0.1:9999\n' > /tmp/lictor-demo/targets.yml
#   cd lictor && env -u PROMPT_COMMAND vhs docs/art/demo.tape   (-u kills the host shell's starship prompt hook noise)
Output docs/art/demo.gif
Set Shell bash
Set FontSize 16
Set Width 1200
Set Height 620
Set Theme { "name": "Sensationnel", "background": "#0b0b10", "foreground": "#e8e3d5", "cursor": "#d4a017", "black": "#1a1a24", "green": "#7fbf7f", "yellow": "#d4a017", "blue": "#7aa2c4", "red": "#c47f7f", "magenta": "#b48ead", "cyan": "#8ad0c0", "white": "#e8e3d5", "brightBlack": "#55555f" }
Set Margin 36
Set MarginFill "#16161f"
Set Padding 16
Set TypingSpeed 30ms

Type "export PATH=$HOME/projets/blog/draft/lictor/bin:$HOME/.local/share/mise/shims:$PATH; cd /tmp/lictor-demo; export PS1='> '"
Enter
Sleep 300ms
Type "echo '   AUGURE + LICTOR - the auditable exploitation decision layer'"
Enter
Type "echo '   decide with provenance - execute under consent - audit everything'"
Enter
Sleep 1200ms
Sleep 2s
Ctrl+L

Type "# act 0 - the lab comes up: four real vulnerable services"
Enter
Type "docker compose -f $HOME/projets/blog/draft/lictor/lab/docker-compose.yml up -d 2>&1 | tail -2"
Enter
Sleep 3s
Sleep 2s
Ctrl+L

Type "# act 1 - the environment, verified"
Enter
Type "lictor doctor | tail -7"
Enter
Sleep 2500ms
Sleep 2s
Ctrl+L

Type "# act 2 - nmap sees the targets (allowlist-checked, trailed)"
Enter
Type "lictor scan 127.0.0.1 -a targets.yml"
Enter
Sleep 7s
Sleep 2s
Ctrl+L

Type "# act 3 - the bridge: download, ELF-check, profile, record"
Enter
Type "lictor acquire 127.0.0.1:9999 --from http://127.0.0.1:8000/ret2func -a targets.yml"
Enter
Sleep 6s
Sleep 2s
Ctrl+L

Type "# act 4 - augure decides, WITH the rule and the evidence"
Enter
Type "lictor plan target.facts -a targets.yml | grep -v '^  ' | head -7"
Enter
Sleep 6s
Sleep 2s
Ctrl+L

Type "lictor plan target.facts -a targets.yml | grep '<- '"
Enter
Sleep 5s
Sleep 2s
Ctrl+L

Type "# act 5 - consent is TYPED by a human, never a flag"
Enter
Type "export TOKEN=$(echo 127.0.0.1:9999 | lictor authorize 127.0.0.1:9999 -a targets.yml | grep token: | awk '{print $2}') && echo token minted: ${TOKEN:0:8}... valid 15 min"
Enter
Sleep 3500ms
Sleep 2s
Ctrl+L

Type "# act 6 - the closed loop: the executor discovers the exploit in the operator's repos"
Enter
Type "lictor run 127.0.0.1:9999 --facts target.facts -a targets.yml --executor ronin --consent-token $TOKEN | tail -3"
Enter
Sleep 10s
Sleep 2s
Ctrl+L

Type "# act 7 - the audit: every decision, rule, token and outcome is recorded"
Enter
Type "lictor report -o engagement.md"
Enter
Sleep 2s
Type "mise x glow -- glow engagement.md | head -22"
Enter
Sleep 4s
Sleep 2s
Ctrl+L

Type "tail -4 demo-trail.jsonl | jq -r .type"
Enter
Sleep 2500ms
Sleep 6s
