#!/usr/bin/env python3
import os
import sys
import time
import subprocess

def lock_and_encrypt_ram(device_name="sdb"):
    if os.geteuid() != 0:
        print("[-] Ошибка: Run Through sudo")
        sys.exit(1)

    print(f"[*] Blocking device {device_name}...")

    
    subprocess.run("sync", shell=True)

   
    subprocess.run("pkill -9 -x thunar", shell=True, stderr=subprocess.DEVNULL)
    subprocess.run("pkill -9 -f gvfs", shell=True, stderr=subprocess.DEVNULL)
    time.sleep(0.3)

    try:
        mounts = subprocess.check_output("mount | grep sdb", shell=True).decode().split('\n')
        for mount in mounts:
            if mount.strip():
                # Вытаскиваем саму папку монтирования
                target = mount.split()[2]
                print(f"[*] Stopping in folder: {target}")
                subprocess.run(f"fuser -k -9 '{target}'", shell=True, stderr=subprocess.DEVNULL)
                subprocess.run(f"umount -f -l '{target}'", shell=True, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        pass 


    try:
        dm_list = subprocess.check_output("dmsetup ls", shell=True).decode().split('\n')
        for dm in dm_list:
            if dm.strip():
                dm_name = dm.split()[0]
                status = subprocess.check_output(f"dmsetup status {dm_name}", shell=True).decode()
                if device_name in status or "luks" in dm_name or "secret" in dm_name:
                    print(f"[+] Kernel mapper: {dm_name}. Unmnt...")
                    
                    subprocess.run(f"fuser -k -9 /dev/mapper/{dm_name}", shell=True, stderr=subprocess.DEVNULL)
                    subprocess.run(f"umount -f -l /dev/mapper/{dm_name}", shell=True, stderr=subprocess.DEVNULL)
                    
                    subprocess.run(f"dmsetup remove -f {dm_name}", shell=True, stderr=subprocess.DEVNULL)
                    
                    subprocess.run(f"cryptsetup close {dm_name}", shell=True)
    except Exception as e:
        print(f"[-] Error: {e}")

    subprocess.run("udevadm trigger", shell=True, stderr=subprocess.DEVNULL)
    subprocess.run("blockdev --flushbufs /dev/sdb", shell=True, stderr=subprocess.DEVNULL)

    print("[+]Done kernel level block")

if __name__ == "__main__":
    lock_and_encrypt_ram("sdb")