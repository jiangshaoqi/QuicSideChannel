use std::{net::{IpAddr, Ipv4Addr, SocketAddr}, sync::Arc};

use anyhow::Result;
use pcap::Capture;
use quinn_proto::{DatagramEvent, Endpoint, EndpointConfig};
use rcgen::CertifiedKey;
use rustls::pki_types::{self, PrivatePkcs8KeyDer};


mod monitorconfig;
use monitorconfig::MonitorConfig;



fn parse_udp_packet(data: &[u8]) -> Option<(SocketAddr, SocketAddr, &[u8])> {
    if data.len() < 14 { return None; } // Ethernet header
    
    let ip_packet = &data[14..];
    if ip_packet.len() < 20 { return None; } // IPv4 header
    
    // 检查协议类型
    if ip_packet[9] != 17 { return None; } // UDP
    
    // 提取IP地址
    let src_ip = Ipv4Addr::new(ip_packet[12], ip_packet[13], ip_packet[14], ip_packet[15]);
    let dst_ip = Ipv4Addr::new(ip_packet[16], ip_packet[17], ip_packet[18], ip_packet[19]);
    
    // IP头部长度
    let ip_header_len = ((ip_packet[0] & 0x0F) * 4) as usize;
    if ip_packet.len() < ip_header_len + 8 { return None; }
    
    let udp_packet = &ip_packet[ip_header_len..];
    
    // 提取UDP端口
    let src_port = u16::from_be_bytes([udp_packet[0], udp_packet[1]]);
    let dst_port = u16::from_be_bytes([udp_packet[2], udp_packet[3]]);
    
    // 验证UDP长度
    let udp_len = u16::from_be_bytes([udp_packet[4], udp_packet[5]]) as usize;
    if udp_len < 8 || udp_packet.len() < udp_len { return None; }
    
    let src_addr = SocketAddr::new(IpAddr::V4(src_ip), src_port);
    let dst_addr = SocketAddr::new(IpAddr::V4(dst_ip), dst_port);
    
    // UDP payload
    let payload = &udp_packet[8..udp_len];
    
    Some((src_addr, dst_addr, payload))
}


/// Generate a dummy self-signed certificate, to later pass into the quinn-proto endpoint.
/// Or quinn-proto endpoint would only enter logic for of response event, which prepare to reply RST
fn create_dummy_server_config() -> Result<Arc<quinn_proto::ServerConfig>> {
    // Generate a dummy self-signed certificate for passive monitoring
    let CertifiedKey { cert, signing_key } = rcgen::generate_simple_self_signed(vec!["monitor.local".into()])?;
    let cert_der = cert.der().clone();
    let cert_chain = vec![cert_der];

    let key_pair_der = signing_key.serialize_der();
    let private_key_der = PrivatePkcs8KeyDer::from(key_pair_der);
    let private_key = pki_types::PrivateKeyDer::from(private_key_der);

    let server_config = quinn_proto::ServerConfig::with_single_cert(cert_chain, private_key)?;
    Ok(Arc::new(server_config))
}


fn main() -> Result<()> {

    let monitorconfig = MonitorConfig::from_file("monitorconfig")?;
    let mut capture = Capture::from_device(monitorconfig.interface.as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to create capture device: {}", e))?
        .immediate_mode(true)
        .open()?;

    let _ = capture.filter(monitorconfig.pcap_filter_expression.as_ref(), false);

    // quinn-proto endpoint setup
    let config = EndpointConfig::default();
    let server_config = create_dummy_server_config()?;
    let mut proto_endpoint = Endpoint::new(Arc::new(config), Some(server_config), false, None);



    while let Ok(packet) = capture.next_packet() {

        if let Some((src_addr, _, data)) = parse_udp_packet(&packet) {
            let now = std::time::Instant::now();
            let mut response_buf = Vec::new();
            match proto_endpoint.handle(now, src_addr, None, None, data.into(), &mut response_buf) {
                Some(DatagramEvent::NewConnection(incoming)) => {
                    println!("New connection");
                    let mut response_accept_buf = Vec::new();
                    let another_server_config = create_dummy_server_config()?;
                    // match the application level's incoming.await
                    let (ch, conn) = proto_endpoint.accept(incoming, now, &mut response_accept_buf, Some(another_server_config))
                        .map_err(|_| anyhow::anyhow!("Failed to accept new connection"))?;
                    
                    
                }

                Some(DatagramEvent::ConnectionEvent(_handle, _event)) => {
                    println!("Connection event");
                    // Ignoring errors from dropped connections that haven't yet been cleaned up
                    // received_connection_packet = true;
                    // let _ = self
                    //     .connections
                    //     .senders
                    //     .get_mut(&handle)
                    //     .unwrap()
                    //     .send(ConnectionEvent::Proto(event));
                }

                Some(DatagramEvent::Response(_transmit)) => {
                    println!("Response event");
                    // respond(transmit, &response_buffer, socket);
                }
                None => {}
            }

        }
    }

    Ok(())
}
