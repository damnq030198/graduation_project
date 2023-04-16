from pyspark.ml import Pipeline, PipelineModel
from pyspark.ml.classification import DecisionTreeClassifier,RandomForestClassifier
from pyspark.ml.feature import IndexToString, StringIndexer, VectorIndexer, VectorAssembler
from pyspark.ml.evaluation import MulticlassClassificationEvaluator
from pyspark.mllib.evaluation import MulticlassMetrics
import os
from pyspark.sql import SparkSession, DataFrame
from pyspark.sql.types import *
from pyspark.sql.functions import *
from pyspark.conf import SparkConf
from pyspark import SparkContext
from datetime import datetime
from pyspark.sql import Row
import os
import glob
from functools import reduce
from datetime import datetime
import sys
import json
import re
import extract_features
import pandas  as pd
from pymongo import MongoClient
from collections import defaultdict

os.environ['SPARK_HOME'] = "/opt/spark"
os.environ["PYSPARK_PYTHON"]="/usr/bin/python3"
def loadcols(dataset):
    col=[]
    for x in dataset.columns:
        if x == 'domain' or x == 'label'or '_c0' == x:
	        continue
        col.append(x)
    return col

class Detector:
    spark = SparkSession.builder.master("local[*]").appName("DomainDetector").config("spark.driver.memory", "8g").getOrCreate()
    spark.sparkContext.setLogLevel("ERROR")
    sc = spark.sparkContext
    def __init__(self, datapath="dataset.csv", modelpath="model",mode=1):
        self.datapath = datapath
        if mode == 0:
            self.dataset = self.loadDataset(datapath)
            self.dataset.show()
            (self.trainingData, self.testingData) = self.dataset.randomSplit([0.7, 0.3])
            self.trainingData = self.trainingData.repartition(300).cache()
            self.testingData = self.testingData.repartition(300).cache()
	    
            self.modelpath = modelpath
            modelfile = os.path.join(self.modelpath, "detector")
            if (os.path.exists(modelfile)):
                print("Load model from: ", self.modelpath)
                self.model = PipelineModel.load(modelfile)
            else:
                print("Train new model")
                self.model = self.trainModel(self.dataset)
                
        else:
            self.predictingData = self.loadDataset(datapath)
            self.predictingData = self.predictingData.repartition(300).cache()
            self.modelpath = modelpath
            modelfile = os.path.join(self.modelpath, "detector")
            if (os.path.exists(modelfile)):
                print("Load model from: ", self.modelpath)
                self.model = PipelineModel.load(modelfile)
            else:
                print("Train new model")
                self.model = self.trainModel(self.dataset)
                
    def loadDataset(self, datapath):
        if ".csv" in datapath:
            dataset = self.spark.read.csv(datapath, header=True, inferSchema=True)
            cols =loadcols(dataset)
        assembler = VectorAssembler(inputCols=cols, outputCol="features")
        dataset = assembler.transform(dataset.dropna())
        dataset = dataset.withColumn("labels", dataset['label'])
        return dataset
    
    def trainModel(self, trainingData):
        """ Ham huan luyen du lieu
        Mac dinh training toan bo du lieu trong dataset splitratio 100% training, 0% testing
        """
        labelIndexer = StringIndexer(inputCol="labels", outputCol="indexedLabel").fit(trainingData)
        featureIndexer = VectorIndexer(inputCol="features", outputCol="indexedFeatures",maxCategories=4).fit(trainingData)
        rf = RandomForestClassifier(labelCol="indexedLabel", featuresCol= "indexedFeatures",numTrees=25)
        labelConverter = IndexToString(inputCol="prediction", outputCol="predictedLabel", labels=labelIndexer.labels)
        pipeline = Pipeline(stages=[labelIndexer, featureIndexer, rf, labelConverter])
        model = pipeline.fit(trainingData)
        model.write().overwrite().save(os.path.join(self.modelpath, "detector"))
        return model
    
    def evaluate(self, model=None, trainingData=None, testingData=None):
        """ Ham kiem thu model, in ra man hinh do do chinh xac va thoi gian tinh toan
        """
        time_train = 0
        time_test = 0
        
        if (not trainingData):
            trainingData = self.trainingData
        if (not testingData):
            testingData = self.testingData
        trainingData.show(5)
        if (not model):   
            print("Training...")
            start_train = datetime.now()
            model = self.trainModel(trainingData)
            time_train = datetime.now() - start_train
        
        
        
        print("Testing...")
        start_test = datetime.now()
        predictions = model.transform(testingData)
        time_test = datetime.now() - start_test

        
        print("{:*^100}".format(""))
        print("Training time: ", time_train)
        print("Testing time: ", time_test)
        
        featureImportances = {}
        fi = model.stages[2].featureImportances
        features = loadcols(self.dataset)
        index = 0
        for value in fi:
            featureImportances[features[index]] = value
            index = index + 1
        fiSorted = sorted(featureImportances.items(), key=lambda x: x[1], reverse=True)
        print("{:*^100}".format(" Feature Importances "))
        f = open("features_importance.txt", "w")
        for feature in fiSorted:
            if feature[1] > 0.000:
                print("{!s} : {:.4%}".format(feature[0].strip(), feature[1]))
            f.write("{!s}\n".format(feature[0].strip()))
        f.close()
        
        print("{:*^100}".format(" Evaluate for Flow "))
        
        print("Total predictions:", predictions.count())
        predictions.select("prediction", "indexedLabel", "labels").groupBy("labels").count().show()
        
        predictionAndLabels = predictions.select("prediction", "indexedLabel").rdd
        metrics = MulticlassMetrics(predictionAndLabels)

        print("Confusion Matrix:")
        for line in metrics.confusionMatrix().toArray():
            print(line)
        
        print("TPR: {:.3%} \tFPR: {:.3%}".format(metrics.truePositiveRate(1.0), metrics.falsePositiveRate(1.0)))
        print("TNR: {:.3%} \tFNR: {:.3%}".format(metrics.truePositiveRate(0.0), metrics.falsePositiveRate(0.0)))

        print("Precision: {:.3%} \tRecall: {:.3%} \tAccuracy: {:.3%}".format(metrics.precision(1.0), metrics.recall(1.0), metrics.accuracy))
        
        print(metrics.accuracy)

        print("{:*^100}".format(""))
        
    
    def predict(self):
        predictions = self.model.transform(self.predictingData)
        df= predictions.select('prediction','domain').collect()
        results =[]
        for i in range(len(df)):
            if int(df[i].asDict()["prediction"]) == 0:
                results.append({'domain':df[i].asDict()["domain"],'status':'clean'})
            else:
                results.append({'domain':df[i].asDict()["domain"],'status':'malicious'})
        return results
	
def detect(md,url):	
	if md == 0 :
		detector = Detector(mode=md)
		detector.evaluate()
	elif md == 1 :
            listfeature = defaultdict(list)
            for domain in url:
                extract_features.extract_feature(domain,0,listfeature)
            dict(listfeature)
            filename="predictions.csv"
            df= pd.DataFrame(listfeature)
            df.to_csv(filename, index=False)
            detector = Detector(mode=md,datapath=filename)
            results = detector.predict()
            for result in results:
                add_db(result)
                del result['_id']
            return results
	
import config
mongo = MongoClient(config.MONGO_CONECTION)
mongodb = mongo.ML
collection = mongodb['List']

def add_db(obj):
    _id = collection.insert_one(obj).inserted_id

def search_db(obj):
    result = collection.find_one(obj, {'_id': False})
    return result

def ml(obj):
    results = []
    domains =[]
    for domain in obj:
        result = search_db({'domain':domain})
        if result == None:
            if domain not in domains:
                domains.append(domain)
        else:
            results.append(result)
    if len(domains) != 0:
        data = detect(1,domains)
        results.append(data)
    return results


#print(ml(["facebook.com","google.com","youtube.com","ieee.com","garena.vn"]))