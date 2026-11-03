use std::fs::File;
use std::io::{BufReader, BufWriter};
use bincode::{serialize_into, deserialize_from};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct Data {
    value: i32,
}

fn main() {
    // Example data stored in a vector
    let data_vec = vec![Data { value: 42 }, Data { value: 100 }];

    // Write data to a file
    let file = File::create("data.bin").unwrap();
    let writer = BufWriter::new(file);
    serialize_into(writer, &data_vec).unwrap(); // Serialize the entire vector at once

    // Read data back from the file
    let file = File::open("data.bin").unwrap();
    let reader = BufReader::new(file);
    // Deserialize the vector
    let deserialized_vec: Vec<Data> = deserialize_from(reader).unwrap();

    for (i, data) in deserialized_vec.iter().enumerate() {
        println!("Deserialized {}: {:?}", i, data);
    }
}
