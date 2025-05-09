use dioxus::prelude::{
    component, dioxus_elements, rsx, Element, IntoDynNode, Props, VNode, VirtualDom,
};
use stack_string::StackString;
use std::fmt::Write;

#[cfg(debug_assertions)]
use dioxus::prelude::{GlobalSignal, Readable};

use security_log_analysis_rust::{config::Config, CountryCount};

use security_log_analysis_rust::errors::ServiceError as Error;

pub fn index_body(data: StackString, config: Config) -> Result<String, Error> {
    let mut app = VirtualDom::new_with_props(IndexElement, IndexElementProps { data, config });
    app.rebuild_in_place();
    let mut renderer = dioxus_ssr::Renderer::default();
    let mut buffer = String::new();
    renderer
        .render_to(&mut buffer, &app)
        .map_err(Into::<Error>::into)?;
    Ok(buffer)
}

#[component]
fn IndexElement(data: StackString, config: Config) -> Element {
    let maps_script = config.maps_api_key.as_ref().map(|map_api_key| {
        rsx! {
            script {
                "type": mime::TEXT_JAVASCRIPT.essence_str(),
                src: "https://maps.googleapis.com/maps/api/js?key={map_api_key}",
            }
        }
    });
    let mut script_body = String::new();
    script_body.push_str("\n!function(){\n");
    writeln!(&mut script_body, "\tlet data = {data};").unwrap();
    writeln!(&mut script_body, "\tdraw_map(data);").unwrap();
    script_body.push_str("}()");

    rsx! {
        head {
            script {
                "type": mime::TEXT_JAVASCRIPT.essence_str(),
                src: "https://www.google.com/jsapi"
            },
            script {
                "type": mime::TEXT_JAVASCRIPT.essence_str(),
                src: "/security_log/map_script.js",
            }
        },
        body {
            {maps_script},
            script {
                dangerous_inner_html: "{script_body}",
            }
            div {
                id: "regions_div",
                style: "width: 900px; height: 500px;",
            }
        }
    }
}
