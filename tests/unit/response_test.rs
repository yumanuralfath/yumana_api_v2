use serde::Serialize;
use yumana_api_v2::utils::response::paginated;

#[derive(Serialize)]
struct MockData {
    id: i32,
}

#[test]
fn test_paginated_calculation() {
    let data = vec![MockData { id: 1 }, MockData { id: 2 }];

    // Test case 1: Exact division
    let res = paginated(data, 10, 1, 2);
    assert_eq!(res["pagination"]["total_pages"], 5);
    assert_eq!(res["pagination"]["total"], 10);
    assert_eq!(res["pagination"]["page"], 1);

    // Test case 2: Round up
    let data2 = vec![MockData { id: 1 }];
    let res2 = paginated(data2, 11, 1, 2);
    assert_eq!(res2["pagination"]["total_pages"], 6);
}

#[test]
fn test_paginated_empty() {
    let data: Vec<MockData> = vec![];
    let res = paginated(data, 0, 1, 10);
    assert_eq!(res["pagination"]["total_pages"], 0);
    assert_eq!(res["pagination"]["total"], 0);
}
