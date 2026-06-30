curl -fsSL https://raw.githubusercontent.com/supabase/cli/main/install | bash

curl -fsSL -o /tmp/dbdev.deb https://github.com/supabase/dbdev/releases/download/v0.1.7/dbdev-v0.1.7-linux-amd64.deb
sudo dpkg -i /tmp/dbdev.deb
rm /tmp/dbdev.deb