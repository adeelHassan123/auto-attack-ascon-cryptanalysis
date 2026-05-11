"""CNN (Convolutional Neural Network) for side-channel attacks - STATE OF THE ART."""
from tensorflow.keras.models import Model
from tensorflow.keras.layers import (
    Conv1D, MaxPooling1D, Dense, Dropout,
    BatchNormalization, Input, Add, Activation, GlobalAveragePooling1D, Concatenate,
)
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


def conv_residual_block(x, filters, kernel_size=7, dropout_rate=0.0):
    """Residual block for CNN with batch norm and skip connection."""
    shortcut = x
    
    # First conv + batch norm + activation
    x = Conv1D(filters, kernel_size, padding='same', kernel_initializer='he_normal')(x)
    x = BatchNormalization()(x)
    x = Activation('swish')(x)
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
    
    x = Activation('swish')(x)
    
    return x


def build_cnn(
    input_dim=1551,
    num_classes=6,
    dropout_rate=0.0,
    variable_key=False,
    label_smoothing=0.05,
    use_nonce_aux=False,
):
    """Build CNN with optional public-nonce side input (strongly recommended for ASCON init HW).

    When ``use_nonce_aux`` is True, pass training/prediction data as ``[traces, nonce01]`` where
    ``nonce01`` is float32 shape (N, 16) with bytes scaled to [0, 1] (e.g. uint8 / 255).
    """
    set_random_seeds(42)

    inputs = Input(shape=(input_dim, 1), name='trace')
    model_inputs = [inputs]
    
    if variable_key:
        # DEEPER architecture for variable-key
        # Initial conv with large kernel for broad feature extraction
        x = Conv1D(128, kernel_size=15, padding='same', kernel_initializer='he_normal')(inputs)
        x = BatchNormalization()(x)
        x = Activation('swish')(x)
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

        if use_nonce_aux:
            nonce_in = Input(shape=(16,), name='nonce')
            model_inputs.append(nonce_in)
            nb = Dense(64, kernel_initializer='he_normal')(nonce_in)
            nb = BatchNormalization()(nb)
            nb = Activation('swish')(nb)
            x = Concatenate()([x, nb])

        # Dense layers
        x = Dense(512, kernel_initializer='he_normal')(x)
        x = BatchNormalization()(x)
        x = Activation('swish')(x)
        x = Dropout(dropout_rate)(x)
        
        x = Dense(256, kernel_initializer='he_normal')(x)
        x = BatchNormalization()(x)
        x = Activation('swish')(x)
        x = Dropout(dropout_rate)(x)
    else:
        # Compact architecture for fixed-key to reduce overfitting/memory pressure.
        x = Conv1D(32, kernel_size=9, padding='same', kernel_initializer='he_normal')(inputs)
        x = BatchNormalization()(x)
        x = Activation('swish')(x)
        x = MaxPooling1D(pool_size=2)(x)
        
        x = conv_residual_block(x, 32, kernel_size=7, dropout_rate=dropout_rate)
        x = MaxPooling1D(pool_size=2)(x)
        
        x = conv_residual_block(x, 64, kernel_size=5, dropout_rate=dropout_rate)
        x = MaxPooling1D(pool_size=2)(x)
        
        x = conv_residual_block(x, 128, kernel_size=3, dropout_rate=dropout_rate)
        x = MaxPooling1D(pool_size=2)(x)
        
        x = Conv1D(128, kernel_size=3, padding='same', kernel_initializer='he_normal')(x)
        x = BatchNormalization()(x)
        x = Activation('swish')(x)
        x = GlobalAveragePooling1D()(x)

        if use_nonce_aux:
            nonce_in = Input(shape=(16,), name='nonce')
            model_inputs.append(nonce_in)
            nb = Dense(64, kernel_initializer='he_normal')(nonce_in)
            nb = BatchNormalization()(nb)
            nb = Activation('swish')(nb)
            x = Concatenate()([x, nb])

        # Dense layers
        x = Dense(128, kernel_initializer='he_normal')(x)
        x = BatchNormalization()(x)
        x = Activation('swish')(x)
        x = Dropout(dropout_rate)(x)
        
        x = Dense(64, kernel_initializer='he_normal')(x)
        x = BatchNormalization()(x)
        x = Activation('swish')(x)
        x = Dropout(dropout_rate)(x)
    
    outputs = Dense(num_classes, activation='softmax', kernel_initializer='glorot_uniform')(x)

    model = Model(inputs=model_inputs, outputs=outputs)
    
    # Advanced optimizer
    optimizer = Adam(learning_rate=0.001, beta_1=0.9, beta_2=0.999, epsilon=1e-7)
    
    model.compile(
        optimizer=optimizer,
        loss=CategoricalCrossentropy(label_smoothing=float(label_smoothing)),
        metrics=['accuracy']
    )
    
    return model


def train_cnn(
    model,
    x_train,
    y_train,
    x_val,
    y_val,
    epochs=100,
    batch_size=128,
    model_path='results/cnn_best.keras',
    verbose=1,
    class_weight=None,
    monitor='val_loss',
    monitor_mode='auto',
    early_stopping_patience=15,
    reduce_lr_patience=7,
    nonce_train=None,
    nonce_val=None,
):
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

    if nonce_train is not None:
        fit_x_train = [x_train, nonce_train]
        fit_x_val = [x_val, nonce_val]
    else:
        fit_x_train = x_train
        fit_x_val = x_val

    # Create callbacks
    callbacks = [
        EarlyStopping(
            monitor=monitor,
            mode=monitor_mode,
            patience=early_stopping_patience,
            restore_best_weights=True,
            verbose=verbose
        ),
        ReduceLROnPlateau(
            monitor=monitor,
            mode=monitor_mode,
            factor=0.5,
            patience=reduce_lr_patience,
            min_lr=1e-7,
            verbose=verbose
        ),
        ModelCheckpoint(
            model_path,
            monitor=monitor,
            mode=monitor_mode,
            save_best_only=True,
            verbose=verbose
        )
    ]
    
    history = model.fit(
        fit_x_train, y_train,
        validation_data=(fit_x_val, y_val),
        epochs=epochs,
        batch_size=batch_size,
        class_weight=class_weight,
        callbacks=callbacks,
        verbose=verbose
    )
    
    return history, model
