use crate::alert::AlertDescription;

#[derive(Debug)]
pub enum TlsError {
    SendAlert(AlertDescription),
    RecvAlert(AlertDescription),
    Io(std::io::Error),
}

impl From<std::io::Error> for TlsError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<AlertDescription> for TlsError {
    fn from(value: AlertDescription) -> Self {
        Self::SendAlert(value)
    }
}

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsError::SendAlert(alert_description) => {
                write!(f, "Sent alert {alert_description:?}")
            }
            TlsError::RecvAlert(alert_description) => {
                write!(f, "Received alert {alert_description:?}")
            }
            TlsError::Io(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for TlsError {}
