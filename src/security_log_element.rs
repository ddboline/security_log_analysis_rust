use dioxus::prelude::{
    dioxus_elements, format_args_f, inline_props, rsx, Element, LazyNodes, NodeFactory, Props,
    Scope, VNode, VirtualDom,
};
use stack_string::StackString;
use std::fmt::Write;

use security_log_analysis_rust::CountryCount;

pub fn index_body(data: StackString) -> String {
    let mut app = VirtualDom::new_with_props(index_element, index_elementProps { data });
    app.rebuild();
    dioxus::ssr::render_vdom(&app)
}

#[inline_props]
fn index_element(cx: Scope, data: StackString) -> Element {
    let mut script_body = String::new();
    script_body.push_str("\n!function(){\n");
    writeln!(&mut script_body, "\tlet data = {data};").unwrap();
    writeln!(&mut script_body, "\tdraw_data(data);").unwrap();
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
            script {
                "{script_body}",
            }
            div {
                id: "regions_div",
                style: "width: 900px; height: 500px;",
            }
        }
    })
}
