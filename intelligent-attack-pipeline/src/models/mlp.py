"""MLP (Multi-Layer Perceptron) model for side-channel attacks."""
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout


def build_mlp(input_dim=1551, num_classes=9, dropout_rate=0.0, variable_key=False):
    """Build MLP model for Hamming Weight classification.
    
    Args:
        input_dim: Number of input features (trace samples)
        num_classes: Number of HW classes (0-8 for 8-bit)
        dropout_rate: Dropout rate for regularization
        variable_key: Whether to use variable-key architecture
    
    Returns:
        Compiled Keras model
    """
    model = Sequential()
    
    if variable_key:
        model.add(Dense(512, activation='relu', input_shape=(input_dim,)))
        model.add(Dropout(dropout_rate))
        model.add(Dense(512, activation='relu'))
        model.add(Dropout(dropout_rate))
        model.add(Dense(256, activation='relu'))
    else:
        model.add(Dense(256, activation='relu', input_shape=(input_dim,)))
        model.add(Dense(256, activation='relu'))
    
    model.add(Dense(num_classes, activation='softmax'))
    model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])
    
    return model
