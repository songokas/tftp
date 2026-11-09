//! TFTP server on an ESP32 over Wi-Fi with `std`. See README.md for how to build and flash.

use std::ffi::CStr;
use std::fs;
use std::net::IpAddr;
use std::net::SocketAddr;

use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::hal::peripherals::Peripherals;
use esp_idf_svc::log::EspLogger;
use esp_idf_svc::nvs::EspDefaultNvsPartition;
use esp_idf_svc::sys;
use esp_idf_svc::wifi::AuthMethod;
use esp_idf_svc::wifi::BlockingWifi;
use esp_idf_svc::wifi::ClientConfiguration;
use esp_idf_svc::wifi::Configuration;
use esp_idf_svc::wifi::EspWifi;
use log::error;
use log::info;
use tftp_dus::error::BoxedError;
use tftp_esp32_idf_example::serve;
use tftp_esp32_idf_example::server_config;

const SSID: &str = env!("WIFI_SSID");
const PASSWORD: &str = env!("WIFI_PASSWORD");
const TFTP_PORT: u16 = 69;
const MOUNT_POINT: &CStr = c"/spiffs";
/// Partition name in partitions.csv.
const PARTITION: &CStr = c"storage";
/// Open files at once: one per connection.
const MAX_OPEN_FILES: usize = tftp_esp32_idf_example::MAX_CONNECTIONS as usize;
const WELCOME: &[u8] = b"Hello from an ESP32 running tftp-dus\n";

fn mount_storage() -> Result<(), sys::EspError> {
    let config = sys::esp_vfs_spiffs_conf_t {
        base_path: MOUNT_POINT.as_ptr(),
        partition_label: PARTITION.as_ptr(),
        max_files: MAX_OPEN_FILES,
        format_if_mount_failed: true,
    };
    sys::esp!(unsafe { sys::esp_vfs_spiffs_register(&config) })
}

fn connect_wifi(wifi: &mut BlockingWifi<EspWifi<'static>>) -> Result<IpAddr, BoxedError> {
    wifi.set_configuration(&Configuration::Client(ClientConfiguration {
        ssid: SSID.try_into().map_err(|_| "SSID is too long")?,
        password: PASSWORD.try_into().map_err(|_| "password is too long")?,
        auth_method: AuthMethod::WPA2Personal,
        ..Default::default()
    }))?;
    wifi.start()?;
    info!("Connecting to {SSID}");
    wifi.connect()?;
    wifi.wait_netif_up()?;
    let address = wifi.wifi().sta_netif().get_ip_info()?.ip;
    Ok(IpAddr::V4(address))
}

fn run() -> Result<(), BoxedError> {
    let peripherals = Peripherals::take()?;
    let event_loop = EspSystemEventLoop::take()?;
    let nvs = EspDefaultNvsPartition::take()?;

    mount_storage()?;
    let directory = MOUNT_POINT.to_str()?;
    fs::write(format!("{directory}/hello.txt"), WELCOME)?;

    let mut wifi = BlockingWifi::wrap(
        EspWifi::new(peripherals.modem, event_loop.clone(), Some(nvs))?,
        event_loop,
    )?;
    let address = connect_wifi(&mut wifi)?;
    info!("TFTP server on {address}:{TFTP_PORT}");

    serve(server_config(
        SocketAddr::new(address, TFTP_PORT),
        directory,
    ))?;
    Ok(())
}

fn main() {
    sys::link_patches();
    EspLogger::initialize_default();

    if let Err(e) = run() {
        error!("Server stopped: {e}");
    }
}
