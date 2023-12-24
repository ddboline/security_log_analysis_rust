use dioxus::prelude::{
    component, dioxus_elements, format_args_f, rsx, Element, GlobalAttributes, IntoDynNode,
    LazyNodes, Props, Scope, VNode, VirtualDom,
};
use stack_string::StackString;
use std::fmt::Write;

use security_log_analysis_rust::{config::Config, CountryCount};

pub fn index_body(data: StackString, config: Config) -> String {
    let mut app = VirtualDom::new_with_props(IndexElement, IndexElementProps { data, config });
    drop(app.rebuild());
    dioxus_ssr::render(&app)
}

#[component]
fn IndexElement(cx: Scope, data: StackString, config: Config) -> Element {
    let maps_script = config.maps_api_key.as_ref().map(|map_api_key| {
        rsx! {
            script {
                "type": "text/javascript",
                src: "https://maps.googleapis.com/maps/api/js?key={map_api_key}",
            }
        }
    });
    let mut script_body = String::new();
    script_body.push_str("\n!function(){\n");
    writeln!(&mut script_body, "\tlet data = {data};").unwrap();
    writeln!(&mut script_body, "\tdraw_map(data);").unwrap();
    script_body.push_str("}()");

    cx.render(rsx! {
        head {
            script {
                "type": "text/javascript",
                src: "https://www.google.com/jsapi"
            },
            script {
                "type": "text/javascript",
                src: "/security_log/map_script.js",
            }
        },
        body {
            maps_script,
            script {
                dangerous_inner_html: "{script_body}",
            }
            div {
                id: "regions_div",
                style: "width: 900px; height: 500px;",
            }
        }
    })
}
