let request = require('request');
const rp = require('request-promise');
const cheerio = require('cheerio');

// Mean of detection rates for vulnerable websites class
const vulnerableMean = 0.16
// Mean of detection rates for invulnerable websites class
const invulnerableMean = 0.92
// Vulnerability threshold
const threshold = parseFloat((invulnerableMean + vulnerableMean)/2).toFixed(2)

// Scrape attack vector from OWASP XSS_Filter_Evasion_Cheat_Sheet
let attack_vector = []

const attackVectorScraper = {
  uri: `https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet`,
  transform: function (body) {
    return cheerio.load(body);
  }
}

class Website {
  constructor(url) {
    this.url = url;
    this.failRate = 0;
    this.detectionRate = 0;
    this.failCount = 0;
    this.detectionCount = 0;
    this.label = ''
  }
}

// List of invulnerable website URLs
// let knownInvulnerableURLs = [
//   'https://github.com/search?utf8=✓&q=',
//   'https://www.amazon.com/s/ref=nb_sb_noss_2?url=search-alias%3Daps&field-keywords=',
//   'https://en.wikipedia.org/wiki/',
//   'http://www.thetablet.co.uk/search?word=',
//   'https://www.mcdonalds.com/us/en-us/search-results.html?q=',
//   'https://cugir.library.cornell.edu/?utf8=✓&q=',
//   'https://medium.com/search?q=',
//   'https://www.quora.com/search?q='
// ]

// let websites = []

// for(let i = 0; i < knownInvulnerableURLs.length; i++){
//   let website = new Website(knownInvulnerableURLs[i])
//   websites[i] = website
// }

// List of vulnerable website URLs
// let knownVulnerableURLs = [
//   'https://ieeexplore.ieee.org/search/searchresult.jsp?newsearch=true&queryText=',
//   'https://www.reddit.com/search?q=',
//   'https://www.owasp.org/index.php?search=',
//   'https://www.ox.ac.uk/funnelback/search?query=',
// ]

// let websites = []

// for(let i = 0; i < knownVulnerableURLs.length; i++){
//   let website = new Website(knownVulnerableURLs[i])
//   websites[i] = website
// }

// Websites to be classified
let websiteURLs = [
  'https://ieeexplore.ieee.org/search/searchresult.jsp?newsearch=true&queryText=',
  'https://www.reddit.com/search?q=',
  'https://www.youtube.com/results?search_query=',
  'https://www.owasp.org/index.php?search=',
  'https://www.nytimes.com/search/',
  'https://www.linkedin.com/search/results/index/?keywords=',
  'https://www.ox.ac.uk/funnelback/search?query=',
  'http://localhost/index.php?search='
]

let websites = []

for(let i = 0; i < websiteURLs.length; i++){
  let website = new Website(websiteURLs[i])
  websites[i] = website
}


rp(attackVectorScraper)
  .then(($) => {
    $('pre').each(function(i, elem) {
      attack_vector[i] = $(this).text();
    });

    // The Tester
    // Make a request to each website, and inspect the response
    // Collected data will be used for building the classifier,
    // and then for classification of unseen records
    for(let i = 0; i < websites.length; i++){
      for(let j = 0; j < attack_vector.length - 9; j++){ // Last 9 scripts are not suitable
        url = websites[i].url + attack_vector[j]
        request.get(
          url,
          function (error, response, body) {
            if (!error && response.statusCode == 200) {
                // If the script is reflected to the website,
                // increase the fail count
                if(response.body.includes('alert') !== false || response.body.includes('XSS') !== false || response.body.includes('xss') !== false){
                  websites[i].failCount ++
                }
                else{
                  websites[i].detectionCount ++
                }
            }
            else{
             websites[i].detectionCount ++
            }
          }
        );
      }
    }

  })
  .then(($) => {
    setTimeout(function(){
    // Classify tested websites
    console.log("Mean of detection rates for vulnerable websites class: " + vulnerableMean)
    console.log("Mean of detection rates for invulnerable websites class: " + invulnerableMean)
    console.log("Threshold: " + threshold)
    console.log('****************************************************************************************')
    for(let i = 0; i < websites.length ; i++){
      websites[i].failRate = parseFloat((websites[i].failCount) / (attack_vector.length - 9)).toFixed(2)
      websites[i].detectionRate = parseFloat((websites[i].detectionCount) / (attack_vector.length - 9)).toFixed(2)
      // Minimum Distance Classifier
      // If detection rate of a website is less than the threshold,
      // Then, classify it as 'Vulnerable', since it is closer to mean of that class
      // Else, classify it as 'Invulnerable'
      if( websites[i].detectionRate < threshold){
         websites[i].label = 'Vulnerable'
      }
      else{
         websites[i].label = 'Invulnerable'
      }
      console.log(websites[i].url)
      console.log('Detection Rate ' + websites[i].detectionRate)
      console.log('Label: ' + websites[i].label)
      console.log('*************************************')
    }

    // Model builder
    // let totalDetectionRate = 0
    // for(let i = 0; i < websites.length ; i++){
    //   websites[i].failRate = parseFloat((websites[i].failCount) / (attack_vector.length - 9)).toFixed(2)
    //   websites[i].detectionRate = parseFloat((websites[i].detectionCount) / (attack_vector.length - 9)).toFixed(2)
    //   totalDetectionRate += parseFloat(websites[i].detectionRate)
    // }
    // console.log(websites)
    // console.log()
    // console.log('****************************************************************************************')
    // console.log('Results of the invulnerable training set:')
    //console.log('Detection rate is ' + parseFloat(totalDetectionRate/websites.length).toFixed(2))
    }, 60000);
})
.catch((err) => {
  console.log(err);
});
