#!/usr/bin/env bash
set -eu
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
BIN_DIR="$HOME/.local/bin"
APP_DIR="$HOME/.local/share/applications"
mkdir -p "$BIN_DIR" "$APP_DIR"
cat > "$BIN_DIR/logsentry-gui" <<EOF
#!/usr/bin/env bash
cd "$SCRIPT_DIR"
exec "$SCRIPT_DIR/run-logsentry-gui.sh"
EOF
chmod +x "$BIN_DIR/logsentry-gui"
cat > "$APP_DIR/logsentry-security-center.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=LogSentry Security Center
Comment=Diagnóstico de rede e triagem local de segurança
Exec=$BIN_DIR/logsentry-gui
Terminal=false
Categories=System;Security;Network;
EOF
chmod +x "$APP_DIR/logsentry-security-center.desktop"
echo "Atalho instalado: LogSentry Security Center. Se não aparecer no menu, termina sessão e volta a entrar."
