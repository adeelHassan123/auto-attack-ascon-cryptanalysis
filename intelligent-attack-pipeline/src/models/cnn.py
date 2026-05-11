"""CNN (Convolutional Neural Network) for side-channel attacks - STATE OF THE ART."""
from tensorflow.keras.models import Model
from tensorflow.keras.layers import (
    Conv1D, MaxPooling1D, Flatten, Dense, Dropout,
    BatchNormalization, Input, Add, Activation, GlobalAveragePooling1D
)
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau, ModelCheckpoint
from tensorflow.keras.optimizers import Adam
import tensorflow as tf
import numpy as np
import random


def set_random_seeds(seed=42):
    """Set all random seeds for reproducibility."""
    random.seed(seed)
    np.random.seed(seed)
    tf.random.set_seed(seed)


def conv_residual_block(x, filters, kernel_size=7, dropout_rate=0.0):
    """Residual block for CNN with batch norm and skip connection."""
    shortcut = x
    
    # First conv + batch norm + activation
    x = Conv1D(filters, kernel_size, padding='same', kernel_initializer='he_normal')(x)
    x = BatchNormalization()(x)
    x = tf.nn.swish(x)
    x = Dropout(dropout_rate)(x)
    
    # Second conv + batch norm
    x = Conv1D(filters, kernel_size, padding='same', kernel_initializer='he_normal')(x)
    x = BatchNormalization()(x)
    
    # Skip connection if dimensions match
    if shortcut.shape[-1] == filters:
        x = Add()([shortcut, x])
    elif shortcut.shape[-1] != filters:
        # Match dimensions with 1x1 conv
        shortcut = Conv1D(filters, 1, padding='same', kernel_initializer='he_normal')(shortcut)
        shortcut = BatchNormalization()(shortcut)
        x = Add()([shortcut, x])
    
    x = tf.nn.swish(x)
    
    return x


def build_cnn(input_dim=1551, num_classes=6, dropout_rate=0.0, variable_key=False):
    """Build STATE-OF-THE-ART CNN with residual connections and batch normalization.
    
    Architecture improvements:
    - Deep residual blocks (ResNet style)
    - Batch normalization for stable training
    - Swish activation (better than ReLU)
    - Multiple filter sizes (multi-scale feature extraction)
    - Global average pooling option
    - He initialization
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
    inputs = Input(shape=(input_dim, 1))
    
    if variable_key:
        # DEEPER architecture for variable-key
        # Initial conv with large kernel for broad feature extraction
        x = Conv1D(128, kernel_size=15, padding='same', kernel_initializer='he_normal')(inputs)
        x = BatchNormalization()(x)
        x = tf.nn.swish(x)
        x = MaxPooling1D(pool_size=2)(x)
        x = Dropout(dropout_rate)(x)
        
        # Multiple residual blocks with increasing filters
        x = conv_residual_block(x, 128, kernel_size=11, dropout_rate=dropout_rate)
        x = conv_residual_block(x, 128, kernel_size=11, dropout_rate=dropout_rate)
        x = MaxPooling1D(pool_size=2)(x)
        
        x = conv_residual_block(x, 256, kernel_size=7, dropout_rate=dropout_rate)
        x = conv_residual_block(x, 256, kernel_size=7, dropout_rate=dropout_rate)
        x = conv_residual_block(x, 256, kernel_size=7, dropout_rate=dropout_rate)
        x = MaxPooling1D(pool_size=2)(x)
        
        x = conv_residual_block(x, 512, kernel_size=5, dropout_rate=dropout_rate)
        x = conv_residual_block(x, 512, kernel_size=5, dropout_rate=dropout_rate)
        x = conv_residual_block(x, 512, kernel_size=5, dropout_rate=dropout_rate)
        x = MaxPooling1D(pool_size=2)(x)
        
        # Global average pooling instead of flatten (reduces parameters)
        x = GlobalAveragePooling1D()(x)
        
        # Dense layers
        x = Dense(512, kernel_initializer='he_normal')(x)
        x = BatchNormalization()(x)
        x = tf.nn.swish(x)
        x = Dropout(dropout_rate)(x)
        
        x = Dense(256, kernel_initializer='he_normal')(x)
        x = BatchNormalization()(x)
        x = tf.nn.swish(x)
        x = Dropout(dropout_rate)(x)
    else:
        # DEEPER architecture for fixed-key
        # Initial conv
        x = Conv1D(64, kernel_size=11, padding='same', kernel_initializer='he_normal')(inputs)
        x = BatchNormalization()(x)
        x = tf.nn.swish(x)
        x = MaxPooling1D(pool_size=2)(x)
        
        # Residual blocks
        x = conv_residual_block(x, 64, kernel_size=7, dropout_rate=dropout_rate)
        x = conv_residual_block(x, 64, kernel_size=7, dropout_rate=dropout_rate)
        x = MaxPooling1D(pool_size=2)(x)
        
        x = conv_residual_block(x, 128, kernel_size=5, dropout_rate=dropout_rate)
        x = conv_residual_block(x, 128, kernel_size=5, dropout_rate=dropout_rate)
        x = conv_residual_block(x, 128, kernel_size=5, dropout_rate=dropout_rate)
        x = MaxPooling1D(pool_size=2)(x)
        
        x = conv_residual_block(x, 256, kernel_size=3, dropout_rate=dropout_rate)
        x = conv_residual_block(x, 256, kernel_size=3, dropout_rate=dropout_rate)
        x = conv_residual_block(x, 256, kernel_size=3, dropout_rate=dropout_rate)
        x = MaxPooling1D(pool_size=2)(x)
        
        x = conv_residual_block(x, 512, kernel_size=3, dropout_rate=dropout_rate)
        x = conv_residual_block(x, 512, kernel_size=3, dropout_rate=dropout_rate)
        
        # Flatten
        x = Flatten()(x)
        
        # Dense layers
        x = Dense(512, kernel_initializer='he_normal')(x)
        x = BatchNormalization()(x)
        x = tf.nn.swish(x)
        x = Dropout(dropout_rate)(x)
        
        x = Dense(256, kernel_initializer='he_normal')(x)
        x = BatchNormalization()(x)
        x = tf.nn.swish(x)
        x = Dropout(dropout_rate)(x)
        
        x = Dense(128, kernel_initializer='he_normal')(x)
        x = BatchNormalization()(x)
        x = tf.nn.swish(x)
    
    # Output layer
    outputs = Dense(num_classes, activation='softmax', kernel_initializer='glorot_uniform')(x)
    
    model = Model(inputs=inputs, outputs=outputs)
    
    # Advanced optimizer
    optimizer = Adam(learning_rate=0.001, beta_1=0.9, beta_2=0.999, epsilon=1e-7)
    
    model.compile(
        optimizer=optimizer,
        loss='categorical_crossentropy',
        metrics=['accuracy']
    )
    
    return model


def train_cnn(model, x_train, y_train, x_val, y_val, epochs=100, batch_size=128,
              model_path='results/cnn_best.h5', verbose=1):
    """Train CNN model with overfitting prevention.
    
    Args:
        model: Keras model to train
        x_train: Training features (needs reshape for CNN: (N, samples, 1))
        y_train: Training labels (one-hot)
        x_val: Validation features
        y_val: Validation labels (one-hot)
        epochs: Maximum epochs (default 100)
        batch_size: Batch size (default 128)
        model_path: Path to save best model
        verbose: Verbosity level
    
    Returns:
        history: Training history
        model: Trained model (best weights restored)
    """
    # Reshape for CNN if needed
    if len(x_train.shape) == 2:
        x_train = x_train.reshape((x_train.shape[0], x_train.shape[1], 1))
    if len(x_val.shape) == 2:
        x_val = x_val.reshape((x_val.shape[0], x_val.shape[1], 1))
    
    # Create callbacks
    callbacks = [
        EarlyStopping(
            monitor='val_loss',
            patience=15,  # Increased patience for deeper model
            restore_best_weights=True,
            verbose=verbose
        ),
        ReduceLROnPlateau(
            monitor='val_loss',
            factor=0.5,
            patience=7,  # Increased patience
            min_lr=1e-7,
            verbose=verbose
        ),
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
