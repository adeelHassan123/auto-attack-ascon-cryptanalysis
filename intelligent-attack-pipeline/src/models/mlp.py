"""MLP (Multi-Layer Perceptron) model for side-channel attacks - STATE OF THE ART."""
from tensorflow.keras.models import Model
from tensorflow.keras.layers import (
    Dense, Dropout, BatchNormalization, Input, Add, Activation
)
from tensorflow.keras import activations
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau, ModelCheckpoint
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.losses import CategoricalCrossentropy
import tensorflow as tf
import numpy as np
import random


def set_random_seeds(seed=42):
    """Set all random seeds for reproducibility."""
    random.seed(seed)
    np.random.seed(seed)
    tf.random.set_seed(seed)


def residual_block(x, units, dropout_rate=0.0):
    """Residual block with batch norm and skip connection."""
    shortcut = x
    
    # First dense + batch norm + activation
    x = Dense(units, kernel_initializer='he_normal')(x)
    x = BatchNormalization()(x)
    x = Activation('swish')(x)  # Swish activation (better than ReLU)
    x = Dropout(dropout_rate)(x)
    
    # Second dense + batch norm
    x = Dense(units, kernel_initializer='he_normal')(x)
    x = BatchNormalization()(x)
    
    # Skip connection if dimensions match
    if shortcut.shape[-1] == units:
        x = Add()([shortcut, x])
    
    x = Activation('swish')(x)
    x = Dropout(dropout_rate)(x)
    
    return x


def build_mlp(input_dim=1551, num_classes=6, dropout_rate=0.0, variable_key=False, label_smoothing=0.05):
    """Build STATE-OF-THE-ART MLP with residual connections and batch normalization.
    
    Architecture improvements:
    - Residual blocks with skip connections (ResNet style)
    - Batch normalization for stable training
    - Swish activation (better than ReLU)
    - Deeper network (4-6 layers)
    - He initialization for better weight initialization
    - Adam optimizer with custom learning rate
    
    Args:
        input_dim: Number of input features (trace samples)
        num_classes: Number of HW classes (0-5 for ASCON 5-bit S-box)
        dropout_rate: Dropout rate for regularization
        variable_key: Whether to use variable-key architecture
    
    Returns:
        Compiled Keras model
    """
    set_random_seeds(42)
    
    # Input layer
    inputs = Input(shape=(input_dim,))
    
    if variable_key:
        # DEEPER architecture for variable-key (generalization harder)
        x = Dense(1024, kernel_initializer='he_normal')(inputs)
        x = BatchNormalization()(x)
        x = Activation('swish')(x)
        x = Dropout(dropout_rate)(x)
        
        # Residual blocks
        x = residual_block(x, 1024, dropout_rate)
        x = residual_block(x, 1024, dropout_rate)
        x = residual_block(x, 512, dropout_rate)
        x = residual_block(x, 512, dropout_rate)
        x = residual_block(x, 256, dropout_rate)
        
        # Final dense layers
        x = Dense(256, kernel_initializer='he_normal')(x)
        x = BatchNormalization()(x)
        x = Activation('swish')(x)
        x = Dropout(dropout_rate)(x)
    else:
        # DEEPER architecture for fixed-key
        x = Dense(512, kernel_initializer='he_normal')(inputs)
        x = BatchNormalization()(x)
        x = Activation('swish')(x)
        x = Dropout(dropout_rate)(x)
        
        # Multiple residual blocks
        x = residual_block(x, 512, dropout_rate)
        x = residual_block(x, 512, dropout_rate)
        x = residual_block(x, 256, dropout_rate)
        x = residual_block(x, 256, dropout_rate)
        x = residual_block(x, 128, dropout_rate)
        
        # Final dense
        x = Dense(128, kernel_initializer='he_normal')(x)
        x = BatchNormalization()(x)
        x = Activation('swish')(x)
    
    # Output layer
    outputs = Dense(num_classes, activation='softmax', kernel_initializer='glorot_uniform')(x)
    
    model = Model(inputs=inputs, outputs=outputs)
    
    # Advanced optimizer with learning rate scheduling
    optimizer = Adam(learning_rate=0.001, beta_1=0.9, beta_2=0.999, epsilon=1e-7)
    
    model.compile(
        optimizer=optimizer,
        loss=CategoricalCrossentropy(label_smoothing=float(label_smoothing)),
        metrics=['accuracy']
    )
    
    return model


def train_mlp(model, x_train, y_train, x_val, y_val, epochs=100, batch_size=256,
              model_path='results/mlp_best.keras', verbose=1, class_weight=None):
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
        class_weight=class_weight,
        callbacks=callbacks,
        verbose=verbose
    )
    
    return history, model
