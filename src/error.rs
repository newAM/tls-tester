use crate::AlertDescription;

#[derive(Debug)]
pub enum ServerError {
    SendAlert(AlertDescription),
    RecvAlert(AlertDescription),
    Io(std::io::Error),
}

impl From<std::io::Error> for ServerError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<AlertDescription> for ServerError {
    fn from(value: AlertDescription) -> Self {
        Self::SendAlert(value)
    }
}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerError::SendAlert(alert_description) => {
                write!(f, "Sent alert {alert_description:?}")
            }
            ServerError::RecvAlert(alert_description) => {
                write!(f, "Received alert {alert_description:?}")
            }
            ServerError::Io(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for ServerError {}
