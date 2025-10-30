# CiberVigIA - Monitor de Red Accesible con IA para Hogares y PyMEs

## Descripción
CiberVigIA es un proyecto modular por competencias desarrollado por estudiantes de Ingeniería en Computación (ICOM) del Centro Universitario de Ciencias Exactas e Ingenierías (CUCEI), Universidad de Guadalajara. El sistema es un monitor de red accesible que utiliza inteligencia artificial (IA) para detectar y mitigar amenazas cibernéticas en entornos como hogares y pequeñas y medianas empresas (PyMEs). Integra captura de tráfico en tiempo real, análisis con machine learning (ML), acciones automatizadas (como bloqueo de IPs) y un dashboard intuitivo para usuarios no expertos.

El proyecto se alinea con la estrategia académica de la convocatoria 2025B del CUCEI/DIVTIC, permitiendo acreditar seminarios de integración y laboratorios abiertos mediante un desarrollo tecnológico integral. Enfocado en innovación, resuelve problemas reales como el aumento de ciberataques en México (35,200 millones en Q1 2025) y Jalisco, promoviendo ciberseguridad inclusiva.

## Alineación con la Convocatoria 2025B
- **Plan de Desarrollo Institucional UdeG 2019-2025 Visión 2030:** Innovación tecnológica inclusiva y transformación digital.
- **Plan de Desarrollo del CUCEI 2019-2025 Visión 2030:** Integración ciber-humana y soluciones para problemas reales en computación.
- **Objetivos de Desarrollo Sostenible (ODS):** ODS 9 (Industria, innovación e infraestructura resiliente) y ODS 4 (Educación de calidad, a través de alertas educativas).
- **Requisitos de la Convocatoria:** 
  - Equipo de 3 integrantes (Emmanuel Mateo Gonzalez Zaragoza, Diego Fabio Perez Ramirez, Mariana Ruiz Gonzalez).
  - Asesor desde el inicio: Prof. Pedro Misraim Gomez Rodríguez.
  - Incluye estado del arte, justificación, objetivos, diseño, prototipo funcional, informe técnico y defensa oral.
  - Fechas clave: Exposición (10-14 nov), Premiación (8-12 dic).

## Requisitos e Instalación
### Requisitos
- Python 3.12+ (recomendado para compatibilidad con librerías ML).
- Librerías principales:
  - Scapy (para captura de paquetes): `pip install scapy`. Favor de revisar las dependencias necesarias para el uso de Scapy en su Entorno a traves de la documentación: https://scapy.readthedocs.io/en/latest/installation.html
  - Scikit-learn (para ML): `pip install scikit-learn`
  - Joblib (para guardar modelos): `pip install joblib`
  - Pandas (para preprocesamiento): `pip install pandas`
  - Plyer (para notificaciones): `pip install plyer`
  - Flask/React (para dashboard): `pip install flask` o npm para React.
- Entorno: Linux/Mac recomendado (para iptables y privilegios sudo); Windows posible (WSL).
- Datasets: NSL-KDD o CIC-IDS2017 (descargar manualmente).
- Modelos de IA: [https://drive.google.com/drive/u/1/folders/1yeI0QsZdkIrJMVf3vj80kXn9-iYg9fLc](https://drive.google.com/drive/folders/1yeI0QsZdkIrJMVf3vj80kXn9-iYg9fLc?usp=sharing)

### Instalación
1. Clona el repositorio: `git clone https://github.com/tu-usuario/CiberVigIA-2025B.git`
2. Crea entorno virtual (o ejecutarlo en local): `python -m venv venv; source venv/bin/activate` (Linux/Mac) o `venv\Scripts\activate` (Windows).
3. Instala dependencias: `pip install -r requirements.txt`.
4. Configura VMs para pruebas: VirtualBox con Kali Linux (simular ataques) y Ubuntu (ejecutar monitor).

## Uso
1. **Captura de Tráfico (Fase 1):** Ejecuta `sudo python src/cibervigia_capture.py` para capturar paquetes, filtrar sospechosos (e.g., puertos 20/21 FTP, 22 SSH) y guardar en .pcap. Simula tráfico con nmap en VM.
2. **Preprocesamiento Dataset (Fase 2):** Usa `python src/preprocess_dataset.py` para limpiar NSL-KDD/CIC-IDS2017 (quitar columnas, codificar protocolos).
3. **Entrenamiento ML (Fase 3):** Ejecuta `python src/train_ml_model.py` para entrenar Random Forest/KNN y guardar modelo con joblib.
4. **Integración Real-Time (Fase 4):** Corre `sudo python src/real_time_detection.py` para clasificar tráfico vivo y alertas.
5. **Acciones Automatizadas (Fase 5):** Integra bloqueo IP: `sudo iptables -A INPUT -s <IP> -j DROP`.
6. **Dashboard (Fase 6):** Inicia Flask: `python src/dashboard.py` o React app para ver alertas.
7. **Watson Opcional (Fase 7):** Despliega en IBM Cloud y usa Watson Assistant para explicaciones.

Ejemplo completo: `sudo python main.py` (integra todas fases en un script principal).

## Estructura del Repositorio
- `src/`: Código fuente (e.g., cibervigia_capture.py, train_ml_model.py).
- `data/`: Datasets (raw/ y processed/).
- `docs/`: Overleaf propuesta, diagramas TikZ, informe técnico.
- `tests/`: Pruebas en VMs (scripts nmap para simular amenazas).
- `requirements.txt`: Dependencias.
- `README.md`: Este archivo.
- `.gitignore`: Ignora .pcap, venv.

## Contribuyentes
- Emmanuel Mateo Gonzalez Zaragoza: Backend/ML.
- Diego Fabio Perez Ramirez: Frontend/Dashboard.
- Mariana Ruiz Gonzalez: Testing/Acciones/Frontend.
- Asesor: Prof. Pedro Misraim Gomez Rodríguez.

## Agradecimientos
- Josue Daniel Torres y Ana Sarai Escamilla, Asesores de parte del proyecto IBM.
- Prof. Carlos.

## Licencia
MIT License – Libre para uso académico, con atribución al equipo CUCEI 2025B.
