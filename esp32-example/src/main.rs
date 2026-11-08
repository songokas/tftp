//! TFTP server on an ESP32 over Wi-Fi. See README.md for how to build and flash.

#![no_std]
#![no_main]
#![allow(clippy::result_large_err)]

use core::net::IpAddr;
use core::net::SocketAddr;
use core::time::Duration;

use embassy_futures::block_on;
use esp_hal::clock::CpuClock;
use esp_hal::main;
use esp_hal::rng::Rng;
use esp_hal::timer::timg::TimerGroup;
use esp_radio::wifi::sta::StationConfig;
use esp_radio::wifi::AuthenticationMethodConfig;
use esp_radio::wifi::Config as WifiConfig;
use esp_radio::wifi::Interface as WifiInterface;
use esp_radio::wifi::WifiController;
use esp_radio::wifi::WifiRxToken;
use esp_radio::wifi::WifiTxToken;
use log::error;
use log::info;
use rand::CryptoRng;
use rand::RngCore;
use smoltcp::phy::Device;
use smoltcp::phy::DeviceCapabilities;
use smoltcp::phy::Medium;
use smoltcp::phy::RxToken;
use smoltcp::phy::TxToken;
use smoltcp::time::Instant as NetInstant;
use static_cell::ConstStaticCell;
use static_cell::StaticCell;
use tftp_dus::config::MAX_BLOCKS_FOR_MULTI_READER;
use tftp_dus::config::MAX_CLIENTS;
use tftp_dus::config::PREFERRED_DATA_BLOCK_SIZE;
use tftp_dus::server::server;
use tftp_dus::server::ServerConfig;
use tftp_dus::std_compat::time::Instant;
use tftp_esp32_example::net::Address;
use tftp_esp32_example::net::Memory;
use tftp_esp32_example::net::NetStack;
use tftp_esp32_example::storage::RamDisk;
use tftp_esp32_example::storage::FILE_CAPACITY;

esp_bootloader_esp_idf::esp_app_desc!();

const SSID: &str = env!("WIFI_SSID");
const PASSWORD: &str = env!("WIFI_PASSWORD");
const TFTP_PORT: u16 = 69;
/// Only for esp-radio, which allocates inside the Wi-Fi driver.
const RADIO_HEAP_SIZE: usize = 72 * 1024;
const WELCOME: &[u8] = b"Hello from an ESP32 running tftp-dus\n";

static MEMORY: ConstStaticCell<Memory> = ConstStaticCell::new(Memory::new());
static DISK: RamDisk = RamDisk::new();
static STACK: StaticCell<NetStack<WifiDevice>> = StaticCell::new();

struct WifiDevice(WifiInterface);
struct WifiRx(WifiRxToken);
struct WifiTx(WifiTxToken);

impl RxToken for WifiRx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        self.0.consume_token(|data| f(data))
    }
}

impl TxToken for WifiTx {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        self.0.consume_token(len, f)
    }
}

impl Device for WifiDevice {
    type RxToken<'a> = WifiRx;
    type TxToken<'a> = WifiTx;

    fn receive(&mut self, _timestamp: NetInstant) -> Option<(WifiRx, WifiTx)> {
        self.0.receive().map(|(rx, tx)| (WifiRx(rx), WifiTx(tx)))
    }

    fn transmit(&mut self, _timestamp: NetInstant) -> Option<WifiTx> {
        self.0.transmit().map(WifiTx)
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ethernet;
        capabilities.max_transmission_unit = 1514;
        capabilities
    }
}

/// `Rng` is a true random source while the radio is running.
#[derive(Clone, Copy)]
struct HardwareRng(Rng);

impl RngCore for HardwareRng {
    fn next_u32(&mut self) -> u32 {
        self.0.random()
    }

    fn next_u64(&mut self) -> u64 {
        (u64::from(self.0.random()) << 32) | u64::from(self.0.random())
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.read(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.0.read(dest);
        Ok(())
    }
}

impl CryptoRng for HardwareRng {}

fn custom_getrandom(buffer: &mut [u8]) -> Result<(), getrandom::Error> {
    Rng::new().read(buffer);
    Ok(())
}
getrandom::register_custom_getrandom!(custom_getrandom);

fn microseconds() -> u64 {
    esp_hal::time::Instant::now()
        .duration_since_epoch()
        .as_micros()
}

fn instant() -> Instant {
    Instant::from_time(microseconds)
}

fn connect_wifi(controller: &mut WifiController<'_>) {
    let station = StationConfig::default()
        .with_ssid(SSID.try_into().expect("SSID is too long"))
        .with_authentication(AuthenticationMethodConfig::Wpa2Personal(
            PASSWORD.try_into().expect("password is too long"),
        ));
    controller
        .set_config(&WifiConfig::Station(station))
        .expect("invalid Wi-Fi configuration");
    loop {
        info!("Connecting to {SSID}");
        match block_on(controller.connect_async()) {
            Ok(_) => return,
            Err(e) => error!("Wi-Fi connection failed: {e:?}"),
        }
    }
}

#[main]
fn main() -> ! {
    esp_println::logger::init_logger(log::LevelFilter::Info);
    let peripherals = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));
    esp_alloc::heap_allocator!(size: RADIO_HEAP_SIZE);

    let timer_group = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timer_group.timer0, peripherals.FROM_CPU_INTR0);

    let mut controller =
        WifiController::new(peripherals.WIFI, Default::default()).expect("failed to start Wi-Fi");
    let interface = WifiInterface::station();
    let mac = interface.mac_address();
    connect_wifi(&mut controller);

    let rng = HardwareRng(Rng::new());
    let seed = u64::from(rng.0.random());
    let stack: &'static NetStack<WifiDevice> = STACK.init(NetStack::new(
        WifiDevice(interface),
        mac,
        Address::Dhcp,
        MEMORY.take(),
        microseconds,
        seed,
    ));
    let address = stack.wait_for_address();
    info!("TFTP server on {address}:{TFTP_PORT}");

    if !DISK.insert("hello.txt", WELCOME) {
        error!("Could not store hello.txt");
    }

    let config = ServerConfig {
        listen: SocketAddr::new(IpAddr::V4(address), TFTP_PORT),
        directory: "/".parse().expect("short path"),
        allow_overwrite: true,
        max_window_size: MAX_BLOCKS_FOR_MULTI_READER,
        request_timeout: Duration::from_secs(15),
        max_connections: MAX_CLIENTS,
        max_file_size: FILE_CAPACITY as u64,
        max_block_size: PREFERRED_DATA_BLOCK_SIZE,
        authorized_keys: None,
        private_key: None,
        require_full_encryption: false,
        // smoltcp sockets can not share the listening port
        require_server_port_change: true,
        prefer_seek: false,
        directory_list: None,
        max_directory_depth: 0,
        error_to_authorized_only: false,
    };

    let result = server(
        config,
        |path, _config| DISK.open(path),
        |path, config| DISK.create(path, config.allow_overwrite),
        |listen, socket_id, _reuse, _capacity| stack.create_socket(listen, socket_id),
        |listen, socket_id, client| stack.create_bound_socket(listen, socket_id, client),
        instant,
        rng,
    );
    if let Err(e) = result {
        error!("Server stopped: {e}");
    }
    loop {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    esp_println::println!("{info}");
    loop {
        core::hint::spin_loop();
    }
}
