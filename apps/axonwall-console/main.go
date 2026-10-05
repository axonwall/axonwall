package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
)

func printBanner() {
	fmt.Println("==================================================================")
	fmt.Println("             Axonwall Linux & nftables Firewall Console           ")
	fmt.Println("==================================================================")
	fmt.Println("")

	// Display current interface IPs
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if (iface.Flags&net.FlagUp) != 0 && (iface.Flags&net.FlagLoopback) == 0 {
				addrs, _ := iface.Addrs()
				var ipList []string
				for _, a := range addrs {
					ipList = append(ipList, a.String())
				}
				if len(ipList) > 0 {
					fmt.Printf("  * %-8s (%s): %s\n", iface.Name, "Up", strings.Join(ipList, ", "))
				}
			}
		}
	}
	fmt.Println("")
	fmt.Println("  Web Management GUI: http://<LAN_IP>:3000 / https://<LAN_IP>:443")
	fmt.Println("==================================================================")
	fmt.Println(" 1) Interfaces Overview & IPs")
	fmt.Println(" 2) Ping Host / Gateway")
	fmt.Println(" 3) View Active nftables Chains")
	fmt.Println(" 4) Test Commit-Confirm Status")
	fmt.Println(" 5) Reboot System")
	fmt.Println(" 6) Power Off System")
	fmt.Println(" 0) Exit / Shell")
	fmt.Println("==================================================================")
	fmt.Print("Enter option: ")
}

func main() {
	reader := bufio.NewReader(os.Stdin)

	for {
		printBanner()
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		switch choice {
		case "1":
			fmt.Println("\n--- Network Interfaces ---")
			cmd := exec.Command("ip", "-br", "addr")
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			_ = cmd.Run()
			fmt.Println("\nPress Enter to continue...")
			_, _ = reader.ReadString('\n')

		case "2":
			fmt.Print("\nEnter target IP or hostname to ping: ")
			target, _ := reader.ReadString('\n')
			target = strings.TrimSpace(target)
			if target != "" {
				cmd := exec.Command("ping", "-c", "4", target)
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				_ = cmd.Run()
			}
			fmt.Println("\nPress Enter to continue...")
			_, _ = reader.ReadString('\n')

		case "3":
			fmt.Println("\n--- nftables Table inet axonwall ---")
			cmd := exec.Command("nft", "list", "table", "inet", "axonwall")
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				fmt.Println("No active table inet axonwall loaded.")
			}
			fmt.Println("\nPress Enter to continue...")
			_, _ = reader.ReadString('\n')

		case "4":
			fmt.Println("\n--- Agent Status ---")
			fmt.Println("Checking /run/axonwall/agent.sock ...")
			if _, err := os.Stat("/run/axonwall/agent.sock"); err == nil {
				fmt.Println("Agent socket active.")
			} else {
				fmt.Println("Agent socket not found (offline).")
			}
			fmt.Println("\nPress Enter to continue...")
			_, _ = reader.ReadString('\n')

		case "5":
			fmt.Print("\nAre you sure you want to reboot? (y/N): ")
			ans, _ := reader.ReadString('\n')
			if strings.ToLower(strings.TrimSpace(ans)) == "y" {
				fmt.Println("Rebooting system...")
				_ = exec.Command("systemctl", "reboot").Run()
			}

		case "6":
			fmt.Print("\nAre you sure you want to power off? (y/N): ")
			ans, _ := reader.ReadString('\n')
			if strings.ToLower(strings.TrimSpace(ans)) == "y" {
				fmt.Println("Powering off...")
				_ = exec.Command("systemctl", "poweroff").Run()
			}

		case "0":
			fmt.Println("Exiting console.")
			return

		default:
			fmt.Println("Invalid selection.")
		}
	}
}
