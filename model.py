import pandas as pd
import numpy as np
import pickle
from sklearn.preprocessing import MinMaxScaler
import tensorflow as tf
from tensorflow.keras import Sequential
from tensorflow.keras.layers import Dense
import matplotlib.pyplot as plt

def set_data(csv_path='data.csv'):
    selected_columns = [
        ' Destination Port', ' Flow Duration', ' Total Fwd Packets', ' Total Backward Packets',
        'Total Length of Fwd Packets', ' Total Length of Bwd Packets',
        ' Fwd Packet Length Mean', ' Fwd Packet Length Std', ' Fwd Packet Length Min', ' Fwd Packet Length Max',
        'Flow Bytes/s', ' Flow Packets/s'
    ]

    df = pd.read_csv(csv_path)
    df_selected = df[selected_columns]

    df_selected.replace([np.inf, -np.inf], np.nan, inplace=True)
    df_selected.dropna(inplace=True)

    scaler = MinMaxScaler()
    df_scaled = pd.DataFrame(scaler.fit_transform(df_selected), columns=selected_columns)

    with open("scaler.pkl", "wb") as f:
        pickle.dump(scaler, f)

    data = df_scaled.values
    return data

def set_model(input_dim):
    model = Sequential([
    Dense(8, activation='relu', input_shape=(input_dim,)),
    Dense(4, activation='relu'),
    Dense(8, activation='relu'),
    Dense(input_dim, activation='sigmoid')
    ])
    model.compile(optimizer='adam', loss='mse', metrics=['accuracy'])
    return model

def show_history(history):
    plt.figure()
    plt.plot(history.history['loss'], label='Training Loss')
    plt.plot(history.history['val_loss'], label='Validation Loss')
    plt.xlabel('Epochs')
    plt.ylabel('Loss')
    plt.legend()
    plt.title('Loss over epochs')
    plt.show()

def main():
    data = set_data('data.csv')

    input_dim = data.shape[1]
    model = set_model(input_dim)

    history = model.fit(
    data, data,
    epochs=5,
    batch_size=32,
    shuffle=True,
    validation_split=0.1
    )

    data_pred = model.predict(data)
    train_mse = np.mean(np.power(data - data_pred, 2), axis=1)
    mean_mse = np.mean(train_mse)
    std_mse = np.std(train_mse)
    threshold = mean_mse + 3 * std_mse
    print(threshold)

    show_history(history)

    model.save("model.keras")

if __name__ == "__main__":
    main()