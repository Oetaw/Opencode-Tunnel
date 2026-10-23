use std::sync::Mutex;

use async_trait::async_trait;
use snow::params::NoiseParams;
use snow::{Builder, HandshakeState, TransportState};

use crate::error::SecurityError;
use crate::identity::{Identity, PublicKeyBytes};

const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
const NOISE_PROLOGUE: &[u8] = b"oct/1 noise-xx";
const NOISE_MAGIC: &[u8; 5] = b"OCTN1";
const MAX_HANDSHAKE_MESSAGE: usize = 4096;
const TAG_LEN: usize = 16;

/// Raw handshake carrier. Implementations must deliver binary messages in
/// order and preserve message boundaries; they must not log the bytes.
#[async_trait]
pub trait NoiseIo: Send + Sync {
    async fn send_handshake(&self, message: Vec<u8>) -> Result<(), SecurityError>;
    async fn recv_handshake(&self) -> Result<Vec<u8>, SecurityError>;
}

pub struct NoiseHandshake {
    state: HandshakeState,
}

impl NoiseHandshake {
    pub fn initiator(identity: &Identity) -> Result<Self, SecurityError> {
        let params: NoiseParams = NOISE_PARAMS.parse().map_err(|_| SecurityError::Handshake)?;
        let state = Builder::new(params)
            .local_private_key(identity.secret())
            .prologue(NOISE_PROLOGUE)
            .build_initiator()
            .map_err(|_| SecurityError::Handshake)?;
        Ok(Self { state })
    }

    pub fn responder(identity: &Identity) -> Result<Self, SecurityError> {
        let params: NoiseParams = NOISE_PARAMS.parse().map_err(|_| SecurityError::Handshake)?;
        let state = Builder::new(params)
            .local_private_key(identity.secret())
            .prologue(NOISE_PROLOGUE)
            .build_responder()
            .map_err(|_| SecurityError::Handshake)?;
        Ok(Self { state })
    }

    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, SecurityError> {
        let mut output = vec![0u8; payload.len() + 128];
        let len = self
            .state
            .write_message(payload, &mut output)
            .map_err(|_| SecurityError::Handshake)?;
        output.truncate(len);
        Ok(output)
    }

    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>, SecurityError> {
        if message.is_empty() || message.len() > MAX_HANDSHAKE_MESSAGE {
            return Err(SecurityError::TooLarge);
        }
        let mut output = vec![0u8; message.len()];
        let len = self
            .state
            .read_message(message, &mut output)
            .map_err(|_| SecurityError::Handshake)?;
        output.truncate(len);
        Ok(output)
    }

    pub fn is_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }

    pub fn remote_static(&self) -> Option<PublicKeyBytes> {
        self.state
            .get_remote_static()
            .and_then(|bytes| bytes.try_into().ok())
    }

    pub fn into_session(self) -> Result<NoiseSession, SecurityError> {
        if !self.state.is_handshake_finished() {
            return Err(SecurityError::Handshake);
        }
        let peer_static = self
            .state
            .get_remote_static()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(SecurityError::Handshake)?;
        let transport = self
            .state
            .into_transport_mode()
            .map_err(|_| SecurityError::Handshake)?;
        Ok(NoiseSession {
            transport: Mutex::new(transport),
            peer_static,
        })
    }
}

/// Authenticated transport cipher. A single mutex serializes nonce allocation;
/// no await is held while encrypting or decrypting.
pub struct NoiseSession {
    transport: Mutex<TransportState>,
    peer_static: PublicKeyBytes,
}

impl NoiseSession {
    pub fn peer_static(&self) -> PublicKeyBytes {
        self.peer_static
    }

    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, SecurityError> {
        if plaintext.len().saturating_add(TAG_LEN) > u16::MAX as usize {
            return Err(SecurityError::TooLarge);
        }
        let mut output = vec![0u8; plaintext.len() + TAG_LEN];
        let mut transport = self.transport.lock().expect("noise transport lock");
        let len = transport
            .write_message(plaintext, &mut output)
            .map_err(|_| SecurityError::Transport)?;
        output.truncate(len);
        Ok(output)
    }

    pub fn rekey_outgoing(&self) {
        self.transport
            .lock()
            .expect("noise transport lock")
            .rekey_outgoing();
    }

    pub fn rekey_incoming(&self) {
        self.transport
            .lock()
            .expect("noise transport lock")
            .rekey_incoming();
    }

    pub fn open(&self, ciphertext: &[u8]) -> Result<Vec<u8>, SecurityError> {
        if ciphertext.len() < TAG_LEN {
            return Err(SecurityError::Transport);
        }
        let mut output = vec![0u8; ciphertext.len() - TAG_LEN];
        let mut transport = self.transport.lock().expect("noise transport lock");
        let len = transport
            .read_message(ciphertext, &mut output)
            .map_err(|_| SecurityError::Transport)?;
        output.truncate(len);
        Ok(output)
    }
}

impl std::fmt::Debug for NoiseSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoiseSession")
            .field(
                "peer_static",
                &crate::identity::fingerprint(&self.peer_static),
            )
            .finish()
    }
}

pub async fn client_handshake(
    io: &dyn NoiseIo,
    identity: &Identity,
    pinned_host: &PublicKeyBytes,
) -> Result<NoiseSession, SecurityError> {
    let mut handshake = NoiseHandshake::initiator(identity)?;
    let first = handshake.write_message(&[])?;
    io.send_handshake(frame(&first)).await?;
    let second_message = io.recv_handshake().await?;
    let second = unframe(&second_message)?;
    handshake.read_message(second)?;
    let peer = handshake.remote_static().ok_or(SecurityError::Handshake)?;
    if &peer != pinned_host {
        return Err(SecurityError::HostKeyMismatch);
    }
    let third = handshake.write_message(&[])?;
    io.send_handshake(frame(&third)).await?;
    handshake.into_session()
}

pub async fn host_handshake(
    io: &dyn NoiseIo,
    identity: &Identity,
) -> Result<NoiseSession, SecurityError> {
    let mut handshake = NoiseHandshake::responder(identity)?;
    let first_message = io.recv_handshake().await?;
    let first = unframe(&first_message)?;
    handshake.read_message(first)?;
    let second = handshake.write_message(&[])?;
    io.send_handshake(frame(&second)).await?;
    let third_message = io.recv_handshake().await?;
    let third = unframe(&third_message)?;
    handshake.read_message(third)?;
    handshake.into_session()
}

fn frame(message: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(NOISE_MAGIC.len() + message.len());
    framed.extend_from_slice(NOISE_MAGIC);
    framed.extend_from_slice(message);
    framed
}

fn unframe(message: &[u8]) -> Result<&[u8], SecurityError> {
    if message.len() <= NOISE_MAGIC.len()
        || !message.starts_with(NOISE_MAGIC)
        || message.len() > NOISE_MAGIC.len() + MAX_HANDSHAKE_MESSAGE
    {
        return Err(SecurityError::Handshake);
    }
    Ok(&message[NOISE_MAGIC.len()..])
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::sync::{mpsc, Mutex};

    use super::*;

    struct ChannelIo {
        tx: mpsc::Sender<Vec<u8>>,
        rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    }

    #[async_trait]
    impl NoiseIo for ChannelIo {
        async fn send_handshake(&self, message: Vec<u8>) -> Result<(), SecurityError> {
            self.tx
                .send(message)
                .await
                .map_err(|_| SecurityError::Handshake)
        }

        async fn recv_handshake(&self) -> Result<Vec<u8>, SecurityError> {
            self.rx
                .lock()
                .await
                .recv()
                .await
                .ok_or(SecurityError::Handshake)
        }
    }

    fn pair() -> (ChannelIo, ChannelIo) {
        let (client_tx, host_rx) = mpsc::channel(4);
        let (host_tx, client_rx) = mpsc::channel(4);
        (
            ChannelIo {
                tx: client_tx,
                rx: Mutex::new(client_rx),
            },
            ChannelIo {
                tx: host_tx,
                rx: Mutex::new(host_rx),
            },
        )
    }

    #[tokio::test]
    async fn pinned_noise_handshake_produces_matching_transport() {
        let host = Arc::new(Identity::generate());
        let client = Arc::new(Identity::generate());
        let host_key = host.public_key();
        let (client_io, host_io) = pair();
        let (client_session, host_session) = tokio::join!(
            client_handshake(&client_io, &client, &host_key),
            host_handshake(&host_io, &host)
        );
        let client_session = client_session.unwrap();
        let host_session = host_session.unwrap();
        assert_eq!(client_session.peer_static(), host_key);
        assert_eq!(host_session.peer_static(), client.public_key());

        let ciphertext = client_session.seal(b"secret payload").unwrap();
        assert_ne!(ciphertext, b"secret payload");
        assert_eq!(host_session.open(&ciphertext).unwrap(), b"secret payload");
    }

    #[tokio::test]
    async fn wrong_host_pin_is_rejected() {
        let host = Identity::generate();
        let client = Identity::generate();
        let (client_io, host_io) = pair();
        let wrong = [9u8; 32];
        let host_task = tokio::spawn(async move { host_handshake(&host_io, &host).await });
        let result = client_handshake(&client_io, &client, &wrong).await;
        assert!(matches!(result, Err(SecurityError::HostKeyMismatch)));
        host_task.abort();
    }
}
