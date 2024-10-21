import streamlit as st
import time
import tensorflow
from concurrent.futures import ThreadPoolExecutor 
import feature_extraction as fe
import url_trust_index as uti
import numpy as np
import joblib
import os

# Load only the required models
try:
    loaded_decision_tree_model = joblib.load('decision_tree_phishing_model.pkl')
    loaded_random_forest_model = joblib.load('random_forest_phishing_model.pkl')
    loaded_logistic_regression_model = joblib.load('linear_regression_phishing_model.pkl')
except Exception as e:
    st.error(f"Error loading models: {e}")

# Check if the neural network model exists
phishing_model_path = 'phishing_model.h5'
if os.path.exists(phishing_model_path):
    loaded_model = tensorflow.keras.models.load_model(phishing_model_path)

st.title('PhishingGuard: Intelligent Phishing URL Detector')

# PhishingGuard Information
st.write("""
    **PhishingGuard** is an advanced system designed to detect phishing URLs with high accuracy using a combination of machine learning models. 
    The system leverages multiple powerful models such as Decision Tree, Random Forest, and Logistic Regression to classify URLs as either **Legitimate** or **Phishing**. 

    Phishing attacks are a growing concern as malicious actors attempt to trick users into revealing sensitive information. **PhishingGuard** helps protect users by checking URLs against known phishing patterns and utilizing intelligent algorithms to predict potential threats.

    Simply enter a URL, and PhishingGuard will analyze it using its multi-model system to provide a prediction. The system calculates the **Phishing Probability** based on consensus from its models, ensuring a reliable result.

    How it works:
    - **Feature Extraction**: Extracts critical features from the URL.
    - **Model Predictions**: Runs the extracted features through various models (Decision Tree, Random Forest, Logistic Regression, and Neural Network if available).
    - **Phishing Probability**: Determines the likelihood of the URL being a phishing attempt based on the results from the models.
""")

url = st.text_input('Enter URL to check 😀 :')

if st.button('Check'):
    start_time = time.time()  # Record the start time
    progress_text = st.empty()  # Placeholder for displaying elapsed time
    uti_text = st.empty()

    with st.spinner('Checking the URL...'):
        if not url:
            st.warning('Please enter a URL to check')
            st.stop()  # Stop further execution
        if not (url.startswith('http') or url.startswith('https')):
            st.warning('Please enter a valid URL with http or https protocol included! (Complete Address)')
            st.stop()  # Stop further execution
            
        try:
            with ThreadPoolExecutor() as executor:
                extracted_parameters_future = executor.submit(fe.extract_url, url)
                uti_future = executor.submit(uti.calculate_uti, url)
            
            extracted_parameters = extracted_parameters_future.result()
            uti_value = uti_future.result()
        except Exception as e:
            st.error(f'Error in extraction of features: {e}')
            st.stop()  # Stop further execution

        input_data = np.expand_dims(extracted_parameters, axis=0)
        
        # Initialize results storage
        results = {}
        
        try:
            # Use the selected models for prediction and store the results
            dt_pred = loaded_decision_tree_model.predict([extracted_parameters])[0]
            rf_pred = loaded_random_forest_model.predict([extracted_parameters])[0]
            lr_pred = loaded_logistic_regression_model.predict([extracted_parameters])[0]
            
            # Add results to the dictionary
            results['Decision Tree'] = 'Phishing' if dt_pred == 1 else 'Legitimate'
            results['Random Forest'] = 'Phishing' if rf_pred == 1 else 'Legitimate'
            results['Linear Regression'] = 'Phishing' if lr_pred == 1 else 'Legitimate'
            
            # Neural Network prediction (if it exists)
            if os.path.exists(phishing_model_path):
                prediction_neural = loaded_model.predict(input_data)
                prediction_neural = (prediction_neural >= 0.5).astype(int)
                results['Neural Network'] = 'Phishing' if prediction_neural[0][0] == 1 else 'Legitimate'
        except Exception as e:
            st.error(f'Error during prediction: {e}')
            st.stop()  # Stop further execution
        
        # Show the results in a table
        st.write("### Prediction Results from Models:")
        model_results_df = {
            "Model": list(results.keys()),
            "Prediction": list(results.values())
        }
        st.table(model_results_df)

        # Count phishing predictions
        phishing_count = list(results.values()).count('Phishing')
        
        # Determine phishing probability
        if phishing_count >= 2:
            confidence_score = (phishing_count / len(results)) * 100
            st.error(f"The URL is likely phishing with a confidence of {confidence_score:.2f}%")
        else:
            st.success('The URL is legitimate')

        # Show the URL Trust Index
        if uti_value >= 7:
            uti_text.write(f'URL Trust Index: :green[{uti_value}]')
        elif uti_value >= 5.5 and uti_value < 7:
            uti_text.write(f'URL Trust Index: :yellow[{uti_value}]')
        else:
            uti_text.write(f'URL Trust Index: :red[{uti_value}]')

        end_time = time.time()  
        elapsed_time = end_time - start_time
        progress_text.write(f":rainbow[Time taken to check the URL: {elapsed_time:.2f} seconds]")

if st.button("Learn More"):
    stream_data()  # Ensure this function is defined somewhere if it's being used
