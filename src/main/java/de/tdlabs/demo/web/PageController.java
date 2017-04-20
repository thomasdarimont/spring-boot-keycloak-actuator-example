package de.tdlabs.demo.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
class PageController {

  @GetMapping("/")
  String index(){
    return "index";
  }
}
