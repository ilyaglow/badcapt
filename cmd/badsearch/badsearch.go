package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/olivere/elastic"
)

const (
	indexName       = "badcapt"
	docType         = "bcrecord"
	aggregationName = "distinct_ip"
	fieldName       = "src_ip.keyword"
	bucketSize      = 10000
)

func main() {
	elasticURL := flag.String("e", "localhost:9200", "Elastic URL")
	elasticBasicLogin := flag.String("l", "", "Elastic basic auth login")
	elasticBasicPassword := flag.String("p", "", "Elastic basic auth password")
	flag.Parse()

	opts := []elastic.ClientOptionFunc{
		elastic.SetURL(*elasticURL),
		elastic.SetSniff(false),
		elastic.SetBasicAuth(*elasticBasicLogin, *elasticBasicPassword),
	}

	client, err := elastic.NewClient(opts...)
	if err != nil {
		panic(err)
	}

	tagg := elastic.NewTermsAggregation().Field(fieldName).Size(bucketSize).OrderByCountDesc()
	searchResult, err := client.Search().
		Index(indexName).
		Type(docType).
		Query(elastic.NewRangeQuery("date").Gt("now-1d").Lt("now")).
		Aggregation(aggregationName, tagg).
		Do(context.Background())
	if err != nil {
		panic(err)
	}

	agg, found := searchResult.Aggregations.Terms(aggregationName)
	if !found {
		return
	}

	for _, bucket := range agg.Buckets {
		fmt.Printf("%s\n", bucket.Key)
	}
}
