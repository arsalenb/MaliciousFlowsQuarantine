package net.floodlightcontroller.unipi.maliciousflowsquarantine.api;

import org.restlet.Context;
import org.restlet.Restlet;
import org.restlet.routing.Router;

import net.floodlightcontroller.core.web.ControllerSummaryResource;
import net.floodlightcontroller.core.web.ControllerSwitchesResource;
import net.floodlightcontroller.core.web.LoadedModuleLoaderResource;
import net.floodlightcontroller.restserver.RestletRoutable;
import net.floodlightcontroller.unipi.maliciousflowsquarantine.api.resources.BufferSize;
import net.floodlightcontroller.unipi.maliciousflowsquarantine.api.resources.MarkFlow;
import net.floodlightcontroller.unipi.maliciousflowsquarantine.api.resources.UnmarkFlow;

public class MaliciousFlowsQuarantineWebRoutable implements RestletRoutable {

    @Override
    public Restlet getRestlet(Context context) {
        Router router = new Router(context);


        router.attach("/controller/summary/json", ControllerSummaryResource.class);
        router.attach("/module/loaded/json", LoadedModuleLoaderResource.class);
        router.attach("/controller/switches/json", ControllerSwitchesResource.class);

        // MaliciousFlowsQuarantine resources
        router.attach("/mark", MarkFlow.class);
        router.attach("/unmark/{method}", UnmarkFlow.class);
        router.attach("/buffer/{id}", BufferSize.class);

        return router;
    }

    @Override
    public String basePath() {

        return "/quarantine";
    }
    
}
