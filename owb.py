import requests
import time
import os
import sys
import random
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from eth_account import Account
from eth_account.messages import encode_defunct
from web3 import Web3
from fake_useragent import UserAgent
from colorama import init, Fore, Back, Style

# Init colorama (auto-reset after each print)
init(autoreset=True)

# --- KONFIGURASI ---
RPC_URL = "https://base.meowrpc.com"
CHAIN_ID = 8453
INVITATION_CODE = "H-pmkv-hpqn-9557"
ua = UserAgent()

# --- PROXY SETTING ---
# Format: http://username:password@ip:port
# Kosongkan list kalau tidak pakai proxy
PROXY_LIST = [
    "http://petclruz:shqkcotsudt5@142.111.67.146:5611",
]

w3 = Web3(Web3.HTTPProvider(RPC_URL))

COMMON_HEADERS = {
    'accept': 'application/json',
    'origin': 'https://clashofcoins.com',
    'referer': 'https://clashofcoins.com/',
    'user-agent': ua.random
}

CLAIM_ABI = [
    {
        "inputs": [
            {"internalType": "uint256", "name": "_timestamp", "type": "uint256"},
            {"internalType": "bytes", "name": "_signature", "type": "bytes"}
        ],
        "name": "claimWithSignature",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    }
]

# --- THREAD LOCK untuk print & file ---
print_lock = threading.Lock()
file_lock  = threading.Lock()

# --- COUNTER GLOBAL ---
stats = {"success": 0, "failed": 0, "total": 0}
stats_lock = threading.Lock()

# ─────────────────────────────────────────────
# HELPER PRINT (thread-safe, ada worker tag)
# ─────────────────────────────────────────────
def tprint(msg):
    with print_lock:
        print(msg)

def _tag(worker_id):
    return f"{Fore.BLUE}[W{worker_id}]{Style.RESET_ALL} " if worker_id else ""

def print_info(msg, worker_id=None):
    tprint(f"{_tag(worker_id)}{Fore.CYAN}[*]{Style.RESET_ALL} {msg}")

def print_ok(msg, worker_id=None):
    tprint(f"{_tag(worker_id)}{Fore.GREEN}[OK]{Style.RESET_ALL} {msg}")

def print_warn(msg, worker_id=None):
    tprint(f"{_tag(worker_id)}{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")

def print_fail(msg, worker_id=None):
    tprint(f"{_tag(worker_id)}{Fore.RED}[-]{Style.RESET_ALL} {msg}")

def print_success(msg, worker_id=None):
    tprint(f"{_tag(worker_id)}{Back.GREEN}{Fore.BLACK}[SUCCESS]{Style.RESET_ALL} {Fore.GREEN}{msg}{Style.RESET_ALL}")

def print_failed_tx(msg, worker_id=None):
    tprint(f"{_tag(worker_id)}{Back.RED}{Fore.WHITE}[FAILED]{Style.RESET_ALL} {Fore.RED}{msg}{Style.RESET_ALL}")

def print_separator(label="", worker_id=None):
    line = "─" * 50
    wid  = _tag(worker_id)
    tprint(f"\n{wid}{Fore.MAGENTA}{line}{Style.RESET_ALL}")
    if label:
        tprint(f"{wid}{Fore.MAGENTA}Akun : {Fore.WHITE}{label}{Style.RESET_ALL}")

def print_banner(total_accounts, num_workers):
    print(f"""
{Fore.CYAN}╔══════════════════════════════════════════════════╗
║          CLASH OF COINS - AUTO CLAIM BOT          ║
╚══════════════════════════════════════════════════╝{Style.RESET_ALL}
  {Fore.WHITE}Akun dimuat   : {Fore.YELLOW}{total_accounts}{Style.RESET_ALL}
  {Fore.WHITE}Jumlah worker : {Fore.GREEN}{num_workers}{Style.RESET_ALL}
  {Fore.WHITE}Chain         : {Fore.MAGENTA}Base (ID: {CHAIN_ID}){Style.RESET_ALL}
{Fore.CYAN}══════════════════════════════════════════════════{Style.RESET_ALL}
""")

def print_stats_summary():
    with stats_lock:
        s = stats["success"]
        f = stats["failed"]
        t = stats["total"]
    tprint(f"""
{Fore.CYAN}══════════════════════════════════════════════════{Style.RESET_ALL}
  {Fore.WHITE}RINGKASAN HASIL{Style.RESET_ALL}
  {Fore.GREEN}✔ Berhasil : {s}{Style.RESET_ALL}
  {Fore.RED}✘ Gagal    : {f}{Style.RESET_ALL}
  {Fore.WHITE}▶ Total    : {t}{Style.RESET_ALL}
{Fore.CYAN}══════════════════════════════════════════════════{Style.RESET_ALL}
""")

# ─────────────────────────────────────────────
# INPUT JUMLAH WORKER
# ─────────────────────────────────────────────
def ask_worker_count(max_accounts):
    while True:
        try:
            print(f"\n{Fore.CYAN}┌─────────────────────────────────────────────┐{Style.RESET_ALL}")
            print(f"{Fore.CYAN}│{Style.RESET_ALL}  Total akun terdeteksi  : {Fore.YELLOW}{max_accounts}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}│{Style.RESET_ALL}  Masukkan jumlah worker {Fore.WHITE}(1 – {max_accounts}){Style.RESET_ALL} :")
            print(f"{Fore.CYAN}└─────────────────────────────────────────────┘{Style.RESET_ALL}")
            val = input(f"  {Fore.GREEN}>> {Style.RESET_ALL}").strip()
            num = int(val)
            if 1 <= num <= max_accounts:
                return num
            print(f"  {Fore.RED}[!] Masukkan angka antara 1 dan {max_accounts}{Style.RESET_ALL}")
        except ValueError:
            print(f"  {Fore.RED}[!] Input tidak valid, masukkan angka bulat{Style.RESET_ALL}")

# ─────────────────────────────────────────────
# FUNGSI PROXY
# ─────────────────────────────────────────────
def get_live_proxy(retries=10, backoff_factor=1.5, worker_id=None):
    check_urls = [
        "http://httpbin.org/ip",
        "https://api.ipify.org?format=json",
        "https://ifconfig.me/all.json",
        "https://ip.seeip.org/jsonip?",
        "https://ipinfo.io/json"
    ]

    # Prioritas 1: Dari PROXY_LIST di script
    if PROXY_LIST:
        proxies_list = PROXY_LIST.copy()
    # Prioritas 2: Dari file proxies.txt
    elif os.path.exists("proxies.txt"):
        with open("proxies.txt", "r") as f:
            proxies_list = [l.strip() for l in f if l.strip() and not l.startswith('#')]
    else:
        proxies_list = []

    if not proxies_list:
        print_fail("Proxy tidak diset → jalan tanpa proxy", worker_id)
        return None

    random.shuffle(proxies_list)

    for attempt in range(1, retries + 1):
        for proxy_str in proxies_list:
            proxies_dict = {"http": proxy_str, "https": proxy_str}
            for url in check_urls:
                try:
                    resp = requests.get(url, proxies=proxies_dict, timeout=6)
                    if resp.status_code == 200:
                        try:
                            ip = resp.json().get("origin") or resp.json().get("ip") or "?"
                        except:
                            ip = resp.text.strip()[:40]
                        tprint(f"{_tag(worker_id)}{Fore.GREEN}🟢 Proxy aktif:{Style.RESET_ALL} "
                               f"{Fore.YELLOW}{proxy_str}{Style.RESET_ALL} → IP: {Fore.CYAN}{ip}{Style.RESET_ALL}")
                        return proxies_dict
                except:
                    continue

        wait = backoff_factor ** attempt
        print_warn(f"Semua proxy gagal ({attempt}/{retries}) → tunggu {wait:.1f}s...", worker_id)
        time.sleep(wait)

    print_fail("Tidak ada proxy hidup setelah semua percobaan.", worker_id)
    return None


def request_with_retry(method, url, proxies=None, worker_id=None, **kwargs):
    while True:
        try:
            resp = requests.request(method, url, proxies=proxies, **kwargs)
            if resp.status_code in [200, 201]:
                return resp
            print_warn(f"HTTP {Fore.RED}{resp.status_code}{Style.RESET_ALL} → retry 5s...", worker_id)
            time.sleep(5)
        except Exception as e:
            print_warn(f"Request error: {Fore.RED}{e}{Style.RESET_ALL} → retry 5s...", worker_id)
            time.sleep(5)


def wait_for_balance(address, target_wei, timeout=60):
    start = time.time()
    while time.time() - start < timeout:
        if w3.eth.get_balance(address) >= target_wei:
            return True
        time.sleep(3)
    return False


def refill_logic(target_address, required_wei, worker_id=None):
    try:
        if not os.path.exists("pkutama.txt"):
            print_fail("pkutama.txt tidak ditemukan untuk refill!", worker_id)
            return False

        with open("pkutama.txt", "r") as f:
            master_key = f.read().strip()

        current_bal    = w3.eth.get_balance(target_address)
        amount_to_send = (required_wei - current_bal) + w3.to_wei(0.0001, 'ether')
        print_info(f"Refill {Fore.YELLOW}{w3.from_wei(amount_to_send, 'ether')}{Style.RESET_ALL} ETH "
                   f"→ {Fore.CYAN}{target_address}{Style.RESET_ALL}", worker_id)

        master_acc = Account.from_key(master_key)
        tx = {
            'nonce':    w3.eth.get_transaction_count(master_acc.address),
            'to':       target_address,
            'value':    amount_to_send,
            'gas':      21000,
            'gasPrice': int(w3.eth.gas_price * 1.1),
            'chainId':  CHAIN_ID
        }
        signed   = w3.eth.account.sign_transaction(tx, master_key)
        tx_hash  = w3.eth.send_raw_transaction(signed.raw_transaction)
        w3.eth.wait_for_transaction_receipt(tx_hash)
        return wait_for_balance(target_address, required_wei)
    except Exception as e:
        print_fail(f"Refill gagal: {e}", worker_id)
        return False


def update_user(token, proxies=None, worker_id=None):
    headers = {**COMMON_HEADERS, 'authorization': token, 'content-type': 'application/json'}
    payload = {"invitationCode": INVITATION_CODE, "registrationPage": "agentic"}
    return bool(request_with_retry('PUT', 'https://api.clashofcoins.com/api/user/',
                                   proxies=proxies, headers=headers, json=payload, worker_id=worker_id))


def perform_claim(token, address, private_key, proxies=None, worker_id=None):
    headers = {**COMMON_HEADERS, 'authorization': token}

    update_user(token, proxies, worker_id)
    request_with_retry('POST', 'https://api.clashofcoins.com/api/agentic/join',
                       proxies=proxies, headers=headers, worker_id=worker_id)

    res_sig = request_with_retry(
        'GET', f'https://api.clashofcoins.com/api/agentic/claim-signature?address={address}',
        proxies=proxies, headers=headers, worker_id=worker_id)
    if not res_sig:
        print_fail("Gagal ambil signature", worker_id)
        return False

    data         = res_sig.json()
    contract_addr = Web3.to_checksum_address(data['contractAddress'])
    ts_val       = int(data['ts'])
    sig_hex      = data['signature']

    contract   = w3.eth.contract(address=contract_addr, abi=CLAIM_ABI)
    data_input = contract.encode_abi("claimWithSignature", [ts_val, Web3.to_bytes(hexstr=sig_hex)])

    gas_price    = int(w3.eth.gas_price * 1.1)
    gas_limit    = 200000
    required_wei = gas_price * gas_limit
    current_bal  = w3.eth.get_balance(address)

    if current_bal < required_wei:
        print_warn(f"Saldo kurang ({Fore.RED}{w3.from_wei(current_bal, 'ether')}{Style.RESET_ALL} ETH)", worker_id)
        if not refill_logic(address, required_wei, worker_id):
            print_fail("Refill gagal → skip claim", worker_id)
            return False

    try:
        tx = {
            'nonce':    w3.eth.get_transaction_count(address),
            'to':       contract_addr,
            'value':    0,
            'gas':      gas_limit,
            'gasPrice': gas_price,
            'data':     data_input,
            'chainId':  CHAIN_ID
        }
        signed_tx = w3.eth.account.sign_transaction(tx, private_key)
        tx_hash   = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        print_info(f"Tx Hash: {Fore.YELLOW}{tx_hash.hex()}{Style.RESET_ALL}", worker_id)

        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=180)
        if receipt['status'] == 1:
            print_success(f"Klaim OK → https://basescan.org/tx/{tx_hash.hex()}", worker_id)
            return True
        else:
            print_failed_tx("Transaksi revert", worker_id)
            return False
    except Exception as e:
        print_fail(f"Tx error: {e}", worker_id)
        return False


def sign_in_privy(private_key, proxies=None, worker_id=None):
    try:
        account = Account.from_key(private_key)
        address = Web3.to_checksum_address(account.address)

        res = request_with_retry(
            'POST', 'https://privy.clashofcoins.com/api/v1/siwe/init',
            proxies=proxies,
            headers={**COMMON_HEADERS, 'privy-app-id': 'cm2tj674t004hp714qtb6f0zr'},
            json={"address": address},
            worker_id=worker_id
        )
        if not res: return None, None

        nonce     = res.json()['nonce']
        issued_at = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())

        msg_text = (
            f"clashofcoins.com wants you to sign in with your Ethereum account:\n"
            f"{address}\n\n"
            f"By signing, you are proving you own this wallet and logging in. "
            f"This does not initiate a transaction or cost any fees.\n\n"
            f"URI: https://clashofcoins.com\n"
            f"Version: 1\n"
            f"Chain ID: {CHAIN_ID}\n"
            f"Nonce: {nonce}\n"
            f"Issued At: {issued_at}\n"
            f"Resources:\n"
            f"- https://privy.io"
        )

        msg    = encode_defunct(text=msg_text)
        signed = Account.sign_message(msg, private_key=private_key)

        res_auth = request_with_retry(
            'POST', 'https://privy.clashofcoins.com/api/v1/siwe/authenticate',
            proxies=proxies,
            headers={**COMMON_HEADERS, 'privy-app-id': 'cm2tj674t004hp714qtb6f0zr'},
            json={
                "message":           msg_text,
                "signature":         "0x" + signed.signature.hex(),
                "chainId":           f"eip155:{CHAIN_ID}",
                "walletClientType":  "okx_wallet",
                "connectorType":     "injected",
                "mode":              "login-or-sign-up"
            },
            worker_id=worker_id
        )
        if not res_auth: return None, None
        return res_auth.json().get('token'), address
    except Exception as e:
        print_fail(f"Privy auth error: {e}", worker_id)
        return None, None


# ─────────────────────────────────────────────
# TASK SATU AKUN (dijalankan di thread)
# ─────────────────────────────────────────────
def process_account(pk, worker_id):
    masked = f"{pk[:10]}...{pk[-6:]}"
    print_separator(masked, worker_id)

    proxies = get_live_proxy(retries=8, worker_id=worker_id)

    token, addr = sign_in_privy(pk, proxies, worker_id)
    if not token:
        print_fail("Login gagal, skip...", worker_id)
        with stats_lock:
            stats["failed"] += 1
            stats["total"]  += 1
        return False

    print_ok(f"Login berhasil → {Fore.CYAN}{addr}{Style.RESET_ALL}", worker_id)

    result = perform_claim(token, addr, pk, proxies, worker_id)

    with stats_lock:
        stats["total"] += 1
        if result:
            stats["success"] += 1
        else:
            stats["failed"]  += 1

    if result:
        with file_lock:
            with open("data_berhasil.txt", "a") as f:
                f.write(f"{addr}|{pk}\n")

    delay = random.uniform(1, 2)
    print_info(f"Selesai, jeda {Fore.YELLOW}{delay:.1f}s{Style.RESET_ALL}", worker_id)
    time.sleep(delay)
    return result


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    if not os.path.exists("pk.txt"):
        print_fail("pk.txt tidak ditemukan!")
        return

    with open("pk.txt", "r") as f:
        pks = [line.strip() for line in f if line.strip()]

    if not pks:
        print_fail("pk.txt kosong!")
        return

    # ── User input jumlah worker ──
    num_workers = ask_worker_count(len(pks))

    print_banner(len(pks), num_workers)
    tprint(f"{Back.BLUE}{Fore.WHITE} START {Style.RESET_ALL} "
           f"Menjalankan {Fore.YELLOW}{len(pks)}{Style.RESET_ALL} akun "
           f"dengan {Fore.GREEN}{num_workers}{Style.RESET_ALL} worker paralel...\n")

    # Bagi akun ke worker secara round-robin agar nomor worker tetap konsisten
    tasks = [(pk, (i % num_workers) + 1) for i, pk in enumerate(pks)]

    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        futures = {executor.submit(process_account, pk, wid): pk for pk, wid in tasks}
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print_fail(f"Worker error tidak tertangani: {e}")

    print_stats_summary()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        tprint(f"\n{Fore.YELLOW}⚠  Dihentikan oleh user.{Style.RESET_ALL}")
        print_stats_summary()
