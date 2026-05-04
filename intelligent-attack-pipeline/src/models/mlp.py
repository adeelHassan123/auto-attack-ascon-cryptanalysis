"""MLP (Multi-Layer Perceptron) model for side-channel attacks."""
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau, ModelCheckpoint
import tensorflow as tf
import numpy as np
import random


def set_random_seeds(seed=42):
    """Set all random seeds for reproducibility."""
    random.seed(seed)
    np.random.seed(seed)
    tf.random.set_seed(seed)


def build_mlp(input_dim=1551, num_classes=6, dropout_rate=0.0, variable_key=False):
    """Build MLP model for ASCON S-box Hamming Weight classification.
    
    Args:
        input_dim: Number of input features (trace samples)
        num_classes: Number of HW classes (0-5 for ASCON 5-bit S-box)
        dropout_rate: Dropout rate for regularization
        variable_key: Whether to use variable-key architecture
    
    Returns:
        Compiled Keras model
    """
    set_random_seeds(42)
    
    model = Sequential()
    
    if variable_key:
        # Deeper architecture for variable-key generalization
        model.add(Dense(512, activation='relu', input_shape=(input_dim,)))
        model.add(Dropout(dropout_rate))
        model.add(Dense(512, activation='relu'))
        model.add(Dropout(dropout_rate))
        model.add(Dense(256, activation='relu'))
    else:
        # Standard architecture for fixed-key
        model.add(Dense(256, activation='relu', input_shape=(input_dim,)))
        model.add(Dense(256, activation='relu'))
    
    model.add(Dense(num_classes, activation='softmax'))  # HW 0-5 for ASCON S-box
    model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])
    
    return model


def train_mlp(model, x_train, y_train, x_val, y_val, epochs=100, batch_size=256,
              model_path='results/mlp_best.h5', verbose=1):
    """Train MLP model with overfitting prevention.
    
    Args:
        model: Keras model to train
        x_train: Training features
        y_train: Training labels (one-hot)
        x_val: Validation features
        y_val: Validation labels (one-hot)
        epochs: Maximum epochs (default 100)
        batch_size: Batch size (default 256)
        model_path: Path to save best model
        verbose: Verbosity level
    
    Returns:
        history: Training history
        model: Trained model (best weights restored)
    """
    # Create callbacks for overfitting prevention
    callbacks = [
        # Early stopping: stop if val_loss doesn't improve for 10 epochs
        EarlyStopping(
            monitor='val_loss',
            patience=10,
            restore_best_weights=True,
            verbose=verbose
        ),
        # Reduce learning rate when plateau
        ReduceLROnPlateau(
            monitor='val_loss',
            factor=0.5,
            patience=5,
            min_lr=1e-6,
            verbose=verbose
        ),
        # Save best model
        ModelCheckpoint(
            model_path,
            monitor='val_loss',
            save_best_only=True,
            verbose=verbose
        )
    ]
    
    # Train model
    history = model.fit(
        x_train, y_train,
        validation_data=(x_val, y_val),
        epochs=epochs,
        batch_size=batch_size,
        callbacks=callbacks,
        verbose=verbose
    )
    
    return history, model
