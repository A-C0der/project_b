import pandas as pd
import numpy as np
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.multioutput import MultiOutputClassifier
from sklearn.metrics import accuracy_score
from sklearn.feature_extraction.text import TfidfVectorizer
import json as js
import xlsxwriter

class HistoryAi:
      def analyer(self):
            new_data = {}
            with open('/var/log/squid/access.log.1', 'r') as src:
                for line in src:
                    data = line.strip().split() 
                    if len(data) > max(2, 6):  # Ensure indexes exist
                        key = data[2]  # User IP
                        if not data[6].startswith(('http://', 'https://')):
                            domain = 'https://' + data[6]
                            parsed_url = urlparse(domain)
                            domain = parsed_url.netloc.split(':')[0]

                        if key not in new_data:
                            new_data[key] = [domain]
                        else:
                            if domain not in new_data[key] and domain.strip():  # Avoid duplicates and empty values
                                new_data[key].append(domain)
            return new_data
            
      def ai_and_report(self):
            user_data = self.analyer()
            workbook = xlsxwriter.Workbook('/hdd/ai_project/project_b/report.xlsx')
            ws = workbook.add_worksheet()
            ws.write('A1', 'User IP')
            ws.write('B1', 'Domain')
            ws.write('C1', 'Status')

            with open('history.json', 'r') as ml_data:
                  data = js.load(ml_data)
                  df = pd.DataFrame(data)
                  
                  vectorizer = TfidfVectorizer()
                  domain_vectors = vectorizer.fit_transform(df['domain']).toarray()
                  labels = df[['malicious', 'suspicious']]

                  # Split data for training and testing
                  domain_train, domain_test, labels_train, labels_test = train_test_split(
                      domain_vectors, labels, test_size=0.3, random_state=42
                  )

                  # Train the model
                  rf_classifier = RandomForestClassifier(n_estimators=100, random_state=42)
                  multi_rf_classifier = MultiOutputClassifier(rf_classifier, n_jobs=-1)
                  multi_rf_classifier.fit(domain_train, labels_train)

                  # Predict on test data
                  y_pred = multi_rf_classifier.predict(domain_test)
                  accuracy = accuracy_score(labels_test, y_pred)
                  print(f"Model Accuracy: {accuracy:.2f}")

                  row = 1 
                  
                  for ip, domains in user_data.items():
                        start_row = row  
                        domain_list = []  

                        for dom in domains:
                              if not dom.strip():  
                                  continue

                              domain_vectorized = vectorizer.transform([dom]).toarray()
                              prediction = multi_rf_classifier.predict(domain_vectorized)

                              is_malicious = prediction[0][0] == 1
                              is_suspicious = prediction[0][1] == 1

                              if is_malicious:
                                  domain_list.append((dom, 'Malicious'))
                              if is_suspicious:
                                  domain_list.append((dom, 'Suspicious'))

                      
                        if domain_list:
                            ws.merge_range(start_row, 0, start_row + len(domain_list) - 1, 0, ip)

                        
                        for dom, status in domain_list:
                            ws.write(row, 1, dom)
                            ws.write(row, 2, status)
                            row += 1  
                  
            workbook.close()

history = HistoryAi()
print(history.ai_and_report())

