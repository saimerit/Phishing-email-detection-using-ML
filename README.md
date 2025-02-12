# Phishing Email Detection using Machine Learning

## 📌 Overview
This project aims to develop a **phishing email detection system** using **machine learning techniques**. The model is trained to classify emails as either **phishing** or **legitimate** by analyzing various features such as email content, metadata, and sender details. Additionally, the model has been enhanced to **detect phishing email IDs** along with the usual email content analysis.

The system leverages **multiple machine learning models** and integrates them into a **cascading architecture** to improve accuracy, precision, recall, and F1-score beyond previous benchmarks.

## 🛠 Features
- **Multi-Model Integration:** Combines **Random Forest, SVM, and Logistic Regression** in a cascading fashion.
- **Phishing Email ID Detection:** Analyzes email addresses for signs of phishing.
- **Content-Based Analysis:** Identifies suspicious words, URLs, and patterns in email bodies.
- **Metadata Extraction:** Uses email headers and metadata for additional classification features.
- **High Accuracy:** Aims to surpass an F1-score of **0.9676** and improve overall detection performance.

## 🚀 Installation

### Prerequisites
Ensure you have Python 3.x installed along with the required dependencies.

```sh
pip install -r requirements.txt
```

### Clone the Repository
```sh
git clone https://github.com/saimerit/Phishing-email-detection-using-ML.git
cd Phishing-email-detection-using-ML
```

## 📂 Dataset
This project utilizes a dataset consisting of:
- **Legitimate Emails** 📩
- **Phishing Emails** 🕵️
- **Extracted Features:** Email metadata, header information, domain reputation, content-based analysis, etc.

### Data Preprocessing
1. **Text Cleaning:** Removal of HTML tags, special characters, and stopwords.
2. **Feature Engineering:** Extraction of URLs, sender reputation, and email structure.
3. **Vectorization:** TF-IDF and word embeddings for text features.

## 📊 Methodology
The phishing detection pipeline follows these steps:
1. **Data Collection & Cleaning**
2. **Feature Extraction** (from email metadata, body, headers, and phishing indicators)
3. **Model Training** using different ML algorithms
4. **Model Stacking & Cascading** to improve prediction performance
5. **Evaluation & Optimization** based on accuracy, precision, recall, and F1-score

## 🔍 Machine Learning Models Used
1. **Random Forest Classifier** 🌲
2. **Support Vector Machine (SVM)** 🔷
3. **Logistic Regression** 📈
4. **Hybrid Cascading Model** (combining the above models for improved accuracy)

## 📈 Performance Metrics
Current best performance:
| Metric        | Score  |
|--------------|--------|
| **Accuracy**  | 0.9622 |
| **Precision** | 0.9823 |
| **Recall**    | 0.9534 |
| **F1-Score**  | 0.9676 |

## 🔮 Future Enhancements
- **Deep Learning Integration:** Experimenting with **LSTMs or BERT** for advanced text analysis.
- **Real-Time Detection API:** Deploying the model as an API for real-time phishing detection.
- **Graph-Based Analysis:** Implementing graph-based email sender verification to improve accuracy.

## 🤝 Contributing
We welcome contributions! If you'd like to improve the project, feel free to:
- **Fork the repo**
- **Create a new branch** (`feature-xyz`)
- **Submit a Pull Request**

## 📜 License
This project is licensed under the MIT License.

---
📧 **Author:** [Sai Ardhendu]

🚀 **GitHub:** [https://github.com/saimerit/]

