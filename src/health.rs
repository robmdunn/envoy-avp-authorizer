use tonic::{Request, Response, Status};
use tonic_health::pb::health_server::{Health, HealthServer};
use tonic_health::pb::{HealthCheckRequest, HealthCheckResponse};
use tonic_health::pb::health_check_response::ServingStatus;
use futures_channel::mpsc;
use tracing::{debug, info, trace};

#[derive(Debug, Default)]
pub struct HealthService {}

#[tonic::async_trait]
impl Health for HealthService {
    async fn check(
        &self,
        _request: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        trace!("Health check requested");

        // For now, we'll just always return healthy
        let reply = HealthCheckResponse {
            status: ServingStatus::Serving as i32,
        };
        Ok(Response::new(reply))
    }

    // This type needs to implement Stream, which futures_channel::mpsc::Receiver does
    type WatchStream = mpsc::Receiver<Result<HealthCheckResponse, Status>>;

    async fn watch(
        &self,
        _request: Request<HealthCheckRequest>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        debug!("Health watch stream requested");

        // Create a channel for streaming responses - use a buffer size of 4
        let (mut tx, rx) = mpsc::channel(4);
        
        // Send initial response
        // .unwrap() is safe because this is a buffered channel, it can't fail unless closed
        tx.try_send(Ok(HealthCheckResponse {
            status: ServingStatus::Serving as i32,
        })).unwrap();
        
        // Return the receiver
        Ok(Response::new(rx))
    }
}

pub fn new_health_service() -> HealthServer<HealthService> {
    info!("Initializing health check service");
    let service = HealthService::default();
    HealthServer::new(service)
}