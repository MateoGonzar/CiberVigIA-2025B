import { useEffect, useState } from 'react';
import axios from 'axios';
import Table from 'react-bootstrap/Table';
import 'bootstrap/dist/css/bootstrap.min.css';

interface Alert {
  timestamp: string;
  ip: string;
  port: number;
  pred: string;
  action?: string;
}

function App() {
  const [alerts, setAlerts] = useState<Alert[]>([]);

  // Fetch alertas de backend Flask (ajusta URL si Flask en otro port/host)
  const fetchAlerts = async () => {
    try {
      const response = await axios.get('http://localhost:5000/api/alerts');  // Ajusta a tu Flask endpoint
      setAlerts(response.data);
    } catch (error) {
      console.error("Error fetching alerts:", error);
    }
  };

  // Refresh auto cada 10s
  useEffect(() => {
    fetchAlerts();  // Fetch inicial
    const interval = setInterval(fetchAlerts, 10000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="container">
      <h1 className="text-center my-4">CiberVigIA Dashboard</h1>
      <p className="text-center">Monitor accesible para usuarios no técnicos. Muestra alertas de amenazas detectadas en tiempo real, con explicaciones simples. Actualización automática cada 10 segundos.</p>
      <Table striped bordered hover responsive>
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>IP Fuente -{'>'} IP Destino</th>
            <th>Puerto</th>
            <th>Predicción</th>
            <th>Acción Tomada</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert, index) => (
            <tr key={index} className={alert.pred !== 'BENIGN' ? 'table-danger' : ''}>  # Rojo para sospechosos
              <td>{alert.timestamp}</td>
              <td>{alert.ip}</td>
              <td>{alert.port}</td>
              <td>{alert.pred}</td>
              <td>{alert.action || 'Bloqueo IP y Notificación Enviada'}</td>
            </tr>
          ))}
        </tbody>
      </Table>
      <button className="btn btn-primary" onClick={fetchAlerts}>Refresh Manual</button>
    </div>
  );
}

export default App;