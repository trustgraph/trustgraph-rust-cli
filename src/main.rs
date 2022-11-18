use serde_json::json;
// use clap::error::ErrorKind;
use clap::Parser;

mod cli;
use cli::{Cli, Commands};


/* TODO next:

  decide on some initial use cases

  make ArgGroup
    make prompts that enforce things

  do something with the args - call a API?  write to trustgraph right now?
  what will be the interface between the CLI and the backend?  is there a backend?

  spit out jsonld and optionally pipe to a thing that writes it to various storages or pushes it out

  make separate components for cli, and pipes

*/



fn main() {
  let args = Cli::parse();

  match &args.command {
      Some(Commands::Claim {
        creator,
        target,
        tags,
        description,
        // extra,
        value,
        algorithm, 
        private_key,
        target_format,
        write,
       }) => {

        let john = json!({

          "@context": "https://raw.githubusercontent.com/trustgraph/trustgraph-schema/gh-pages/TrustClaim.jsonld",
          "type": target_format,
          "issuer": creator,
          "issued": "2017-03-04T02:05:07-08:00",
          "claim": {
              "@context": "https://schema.org/",
              "type": "Review",
              "itemReviewed": target,
              "author": creator,
              "keywords": tags,
              "reviewRating": {
                  "@context": "https://schema.org/",
                  "type": "Rating",
                  "bestRating": 1,
                  "worstRating": 0,
                  "ratingValue": value,
                  "description": description
              }
          },
          "signature": {
              "type": format!("sec: {}", algorithm),
              "http://purl.org/dc/terms/created": {
                  "type": "http://www.w3.org/2001/XMLSchema#dateTime",
                  "@value": "2017-03-04T10:05:07Z"
              },
              "http://purl.org/dc/terms/creator": {
                  "id": "EcdsaKoblitz-public-key:020d79074ef137d4f338c2e6bef2a49c618109eccf1cd01ccc3286634789baef4b"
              },
              "sec:domain": "example.com",
              "signature:Value": "IEd/NpCGX7cRe4wc1xh3o4X/y37pY4tOdt8WbYnaGw/Gbr2Oz7GqtkbYE8dxfxjFFYCrISPJGbBNFyaiVBAb6bs="
          }

        });
      },
      Some(Commands::Graph { 
        subcommand,
        perspective,
        creator,
        target,
        tags,
        depth,
        min_value,
        max_value,
       }) => {
        // TODO: Graph command methods
      },
      None => {} // Default method or throw error?
    }


}


#[test]
fn verify_cli() {
    use clap::CommandFactory;
    Cli::command().debug_assert()
}