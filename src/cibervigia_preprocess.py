import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
from imblearn.over_sampling import SMOTE
import numpy as np

def get_column_names(file_path):  # start_line=1 para índice Python (línea 2 en 1-based)
    with open(file_path, 'r') as f:
        lines = f.readlines()
    column_names = []
    attack_types_raw = lines[0].strip()  # Línea 0: tipos de ataques
    attack_types = [attack.strip() for attack in attack_types_raw.split(',')]  # Parsear en lista
    for line in lines:  # Empieza desde línea 2
        if ':' in line:  # Ignora líneas sin ":"
            name = line.split(':')[0].strip()  # Toma antes de ":", quita espacios
            column_names.append(name)
    column_names += ['label']
    return attack_types, column_names

# Paso 1: Cargar datasets
df = pd.read_csv('data/raw/KDD CUP 99/corrected.gz', header=None)
column_names = get_column_names('data/raw/KDD CUP 99/kddcup.names')
attack_types, df.columns = column_names

data1 = pd.read_csv('data/raw/IDS 2017/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv')
data2 = pd.read_csv('data/raw/IDS 2017/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv')
data3 = pd.read_csv('data/raw/IDS 2017/Friday-WorkingHours-Morning.pcap_ISCX.csv')
data4 = pd.read_csv('data/raw/IDS 2017/Monday-WorkingHours.pcap_ISCX.csv')
data5 = pd.read_csv('data/raw/IDS 2017/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv')
data6 = pd.read_csv('data/raw/IDS 2017/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv')
data7 = pd.read_csv('data/raw/IDS 2017/Tuesday-WorkingHours.pcap_ISCX.csv')
data8 = pd.read_csv('data/raw/IDS 2017/Wednesday-workingHours.pcap_ISCX.csv')

# Paso 2: Crear un mismo dataset para CIC
data_list = [data1, data2, data3, data4, data5, data6, data7, data8]

print('Data dimensions: ')
for i, data in enumerate(data_list, start = 1):
  rows, cols = data.shape
  print(f'Data{i} -> {rows} rows, {cols} columns')

data = pd.concat(data_list) # Dataset CIC 2017 concatenado
rows, cols = data.shape

print('New dimension for CIC Dataset:')
print(f'Number of rows: {rows}')
print(f'Number of columns: {cols}')
print(f'Total cells: {rows * cols}')

for d in data_list: del d

rows, cols = df.shape
print(f'Data KDD -> {rows} rows, {cols} columns')

# Paso 3: Mostrar los nombres de las columnas y exploración
print(f'Data KDD -> {df.columns}')
print(f'Data CIC -> {data.columns}')

data.columns = data.columns.str.lstrip()

print('Data KDD:')
print("Forma original:", df.shape)
print("Tipos:", df.dtypes)
print("Missing values:", df.isnull().sum().sum())
print("Duplicados:", df.duplicated().sum())
label_counts = df['label'].value_counts() if 'label' in df else pd.Series()
print("Balance de labels:", label_counts)

# Filtrar clases con pocas muestras (evita error SMOTE)
low_sample_classes = label_counts[label_counts < 2].index
if len(low_sample_classes) > 0:
    print(f"Filtrando clases con <2 muestras: {low_sample_classes}")
    df = df[~df['label'].isin(low_sample_classes)]

print('Data CIC:')
print("Forma original:", data.shape)
print("Tipos:", data.dtypes)
print("Missing values:", data.isnull().sum().sum())
print("Duplicados:", data.duplicated().sum())
label_counts = data['Label'].value_counts() if 'Label' in data else pd.Series()
print("Balance de labels:", label_counts)

# Filtrar clases con pocas muestras (evita error SMOTE)
low_sample_classes = label_counts[label_counts < 2].index
if len(low_sample_classes) > 0:
    print(f"Filtrando clases con <2 muestras: {low_sample_classes}")
    data = data[~data['label'].isin(low_sample_classes)]

# Paso 4: Limpiamos los datos perdidos / duplicados / infinitos
df = df.replace([np.inf, -np.inf], np.nan).fillna(0).drop_duplicates()
data = data.replace([np.inf, -np.inf], np.nan).fillna(0).drop_duplicates()

print('Data cleaning done.')

# Paso 5: Agegamos encodings categoricos
lekdd = LabelEncoder()
for col in ['protocol_type', 'service', 'flag']:
    df[col] = lekdd.fit_transform(df[col])

lecic = LabelEncoder()
for col in data.select_dtypes(include=['object']).columns:
    if col != 'Label':  # Excluye label
        data[col] = lecic.fit_transform(data[col].astype(str))

print('Label encoding done.')

# Paso 6: Scaling numerico
numerical_cols_kdd = df.select_dtypes(include=['int64', 'float64']).columns.drop('label', errors='ignore')
scaler_kdd = StandardScaler()
df[numerical_cols_kdd] = scaler_kdd.fit_transform(df[numerical_cols_kdd])

numerical_cols_cic = data.select_dtypes(include=['int64', 'float64']).columns.drop('Label', errors='ignore')
scaler_cic = StandardScaler()
data[numerical_cols_cic] = scaler_cic.fit_transform(data[numerical_cols_cic])

print('Numeric scaling done.')

# Paso 7: Balanceo (SMOTE) -> Se necesita en ambos datasets
X = df.drop('label', axis=1)
y = df['label']
smote = SMOTE(random_state=42, k_neighbors=1)
X_res, y_res = smote.fit_resample(X, y)
df_balanced = pd.concat([pd.DataFrame(X_res, columns=X.columns), pd.Series(y_res, name='label')], axis=1)

X = data.drop('Label', axis=1)
y = data['Label']
smote = SMOTE(random_state=42, k_neighbors=1)
X_res, y_res = smote.fit_resample(X, y)
data_balanced = pd.concat([pd.DataFrame(X_res, columns=X.columns), pd.Series(y_res, name='Label')], axis=1)

print('SMOTE done.')

# Paso 8: Guardar
df_balanced.to_csv('data/processed/nsl_kdd_clean.csv', index=False)
print("NSL-KDD limpiado guardado.")

data_balanced.to_csv('data/processed/cic_ids2017_clean.csv', index=False)
print("CIC-IDS2017 limpiado guardado.")

