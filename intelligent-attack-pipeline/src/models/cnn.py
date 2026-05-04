"""CNN (Convolutional Neural Network) model for side-channel attacks."""
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Conv1D, MaxPooling1D, Flatten, Dense, Dropout, Reshape


def build_cnn(input_dim=1551, num_classes=9, dropout_rate=0.0, variable_key=False):
    """Build CNN model for Hamming Weight classification.
    
    Args:
        input_dim: Number of input features (trace samples)
        num_classes: Number of HW classes (0-5 for 5-bit ASCON S-box)
        dropout_rate: Dropout rate for regularization
        variable_key: Whether to use variable-key architecture
    
    Returns:
        Compiled Keras model
    """
    model = Sequential()
    
    # Reshape for Conv1D: (batch, samples, channels)
    model.add(Reshape((input_dim, 1), input_shape=(input_dim,)))
    
    # Convolutional layers
    model.add(Conv1D(64, kernel_size=11, activation='relu', padding='same'))
    model.add(MaxPooling1D(pool_size=2))
    model.add(Conv1D(128, kernel_size=7, activation='relu', padding='same'))
    model.add(MaxPooling1D(pool_size=2))
    
    if variable_key:
        model.add(Conv1D(256, kernel_size=5, activation='relu', padding='same'))
        model.add(MaxPooling1D(pool_size=2))
        model.add(Dropout(dropout_rate))
    
    model.add(Flatten())
    
    # Dense layers
    if variable_key:
        model.add(Dense(512, activation='relu'))
        model.add(Dropout(dropout_rate))
        model.add(Dense(256, activation='relu'))
    else:
        model.add(Dense(256, activation='relu'))
    
    model.add(Dense(num_classes, activation='softmax'))
    model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])
    
    return model
